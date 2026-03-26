#!/usr/bin/env python3
"""
AWS IAM Permissiveness Audit — refactor of aws-iam-allactions.py, aws-iam-crossaccount.py, aws-iam-passrole.py etc

"""

import argparse
import concurrent.futures as futures
import csv
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

try:
    import boto3
    from botocore.config import Config as BotoConfig
    from botocore.exceptions import ClientError
except Exception as e:  # pragma: no cover
    print("boto3 is required: pip install boto3", file=sys.stderr)
    raise

# ------------------------- config & defaults -------------------------
DEFAULT_THRESHOLD = 20
DEFAULT_STALE_DAYS = 90  # Credentials unused for this many days are flagged
DEFAULT_SENSITIVE_SERVICES = [
    "iam", "sts", "s3", "kms", "ec2", "lambda", "ecr", "secretsmanager", "ssm", "organizations",
]
# Small seed; you can override/extend via --sensitive-actions-file
SENSITIVE_ACTIONS_SEED = sorted({
    # IAM and identity
    "iam:PassRole", "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:AttachUserPolicy",
    "iam:AttachRolePolicy", "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy",
    "iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
    # STS
    "sts:AssumeRole", "sts:AssumeRoleWithWebIdentity",
    # Data plane / control plane examples
    "s3:PutBucketPolicy", "s3:PutBucketAcl", "s3:PutBucketPublicAccessBlock", "s3:PutObject", "s3:DeleteObject",
    "lambda:CreateFunction", "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration",
    "ec2:RunInstances", "ec2:AssociateIamInstanceProfile", "ec2:ReplaceIamInstanceProfileAssociation",
    "ecr:PutImage", "ecr:BatchDeleteImage",
    "kms:CreateGrant", "kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:EnableKey",
    "secretsmanager:PutSecretValue", "secretsmanager:UpdateSecret", "secretsmanager:DeleteSecret",
    "ssm:SendCommand", "ssm:PutParameter", "ssm:DeleteParameter",
    "organizations:AttachPolicy", "organizations:UpdatePolicy",
})

PRIVESC_RULES = [
    # Policy versioning
    ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
    # Attach or put admin policy
    ["iam:AttachUserPolicy"], 
    ["iam:AttachRolePolicy"],
    ["iam:PutUserPolicy"],
    ["iam:PutRolePolicy"],
    # Update trust and assume
    ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
    # PassRole + compute service
    ["iam:PassRole", "lambda:CreateFunction"],
    ["iam:PassRole", "lambda:UpdateFunctionCode"],
    ["iam:PassRole", "lambda:UpdateFunctionConfiguration"],
    ["iam:PassRole", "ecs:RunTask"],
    ["iam:PassRole", "ec2:RunInstances", "ec2:AssociateIamInstanceProfile"],
    ["iam:PassRole", "ec2:ReplaceIamInstanceProfileAssociation"],
    ["iam:PassRole", "glue:CreateDevEndpoint"],
    ["iam:PassRole", "sagemaker:CreateNotebookInstance"],
    ["iam:PassRole", "codebuild:StartBuild"],
    # Create credentials for higher-priv identity
    ["iam:CreateAccessKey"],
    ["iam:CreateLoginProfile"],
    # Remove or detach boundaries / deny policies
    ["iam:DeleteUserPermissionsBoundary"],
    ["iam:DeleteRolePermissionsBoundary"],
    ["iam:DetachUserPolicy"],
    ["iam:DetachRolePolicy"],
    ["iam:DeleteUserPolicy"],
    ["iam:DeleteRolePolicy"],
    # Key Management Service privilege escalations
    ["kms:CreateGrant", "kms:RetireGrant"],
    ["kms:ScheduleKeyDeletion"],
    ["kms:DisableKey"],
    ["kms:EnableKey"],
    # Secrets Manager privilege escalations
    ["secretsmanager:PutSecretValue"],
    ["secretsmanager:UpdateSecret"],
    ["secretsmanager:DeleteSecret"],
    # S3 bucket policy/ACL modifications that could allow uploading malicious code
    ["s3:PutBucketPolicy"],
    ["s3:PutBucketAcl"],
    ["s3:PutBucketPublicAccessBlock"],
    # CloudFormation create stack with admin role
    ["cloudformation:CreateStack", "iam:PassRole"],
]


# ------------------------- helper utilities -------------------------
def ensure_list(x: Any) -> List[Any]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def flatten_actions(actions: Any) -> List[str]:
    """Return list of actions as lower-case strings (handles str or list)."""
    out: List[str] = []
    for a in ensure_list(actions):
        if not a:
            continue
        out.append(str(a).strip())
    return [s for s in map(str.lower, out) if s]


def normalize_statement(stmt: Dict[str, Any]) -> Tuple[List[str], List[str], List[str], str, Dict[str, Any]]:
    actions = flatten_actions(stmt.get("Action"))
    not_actions = flatten_actions(stmt.get("NotAction"))
    resources = [r if isinstance(r, str) else json.dumps(r) for r in ensure_list(stmt.get("Resource") or ["*"])]
    effect = (stmt.get("Effect") or "Allow").title()
    cond = stmt.get("Condition") or {}
    return actions, not_actions, resources, effect, cond


def is_unrestricted(actions: List[str], resources: List[str], effect: str, cond: Dict[str, Any]) -> bool:
    if effect != "Allow":
        return False
    action_wild = any(a == "*" or a.endswith(":*") for a in actions)
    resource_wild = any(r == "*" or ":*" in r for r in resources)
    return action_wild and resource_wild and not cond


def count_unique_actions(actions: List[str]) -> int:
    return len(set(actions))


def score_finding(impact: float, likelihood: float, exposure: float) -> float:
    # Clamp to 0..10
    impact = max(0.0, min(10.0, impact))
    likelihood = max(0.0, min(10.0, likelihood))
    exposure = max(0.0, min(10.0, exposure))
    raw = impact * likelihood * exposure
    # Normalize to 0–100
    return round(raw / 10.0, 1)

# ------------------------- data models -------------------------
@dataclass
class Attachment:
    type: str  # User | Role | Group
    name: str
    arn: Optional[str]  # may be None; resolved later when needed


@dataclass
class Finding:
    account_id: str
    policy_arn: str
    policy_name: str
    attachment_type: str  # managed | inline | n/a
    principal_type: Optional[str] = None
    principal_name: Optional[str] = None
    principal_arn: Optional[str] = None
    risk_type: str = ""
    detail: str = ""
    action_count: Optional[int] = None
    conditions: Optional[Dict[str, Any]] = None
    explicit_denies: int = 0
    exposure: str = "internal"  # internal | external-account | public
    allowed_examples: Optional[List[str]] = None
    privesc_hits: Optional[List[str]] = None
    severity_score: Optional[float] = None
    remediation: Optional[str] = None
    compliance_frameworks: Optional[List[str]] = None
    days_since_use: Optional[int] = None

# ------------------------- sensitive actions loading -------------------------
def load_sensitive_actions(path: Optional[str]) -> set[str]:
    """
    Load a JSON array of actions (e.g., ["iam:PassRole","s3:PutBucketPolicy"]) as the sensitive set.
    Falls back to SENSITIVE_ACTIONS_SEED if file missing/invalid.
    """
    default = {a.lower() for a in SENSITIVE_ACTIONS_SEED}
    if not path:
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        items = {str(x).lower() for x in data if isinstance(x, str)}
        return items if items else default
    except Exception:
        return default


def has_sensitive(actions: List[str], sensitive_actions_set: set[str]) -> bool:
    """True if wildcard/service:* or any action intersects the sensitive set."""
    actions_l = [a.lower() for a in actions]
    if any(a == "*" or a.endswith(":*") for a in actions_l):
        return True
    return any(a in sensitive_actions_set for a in actions_l)

# ------------------------- boto session helpers -------------------------
def make_session(profile: Optional[str], region: Optional[str]):
    if profile:
        boto3.setup_default_session(profile_name=profile)
    return boto3.session.Session(region_name=region)


def assume_role_if_needed(session, role_arn: Optional[str]):
    if not role_arn:
        return session
    sts = session.client("sts")
    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="iam-permissiveness-audit")
    c = creds["Credentials"]
    return boto3.session.Session(
        aws_access_key_id=c["AccessKeyId"],
        aws_secret_access_key=c["SecretAccessKey"],
        aws_session_token=c["SessionToken"],
        region_name=session.region_name,
    )

# ------------------------- partition & ARN resolution -------------------------
def get_partition_from_sts_arn(sts_arn: str) -> str:
    # e.g., arn:aws:sts::123456789012:assumed-role/...
    try:
        return sts_arn.split(":")[1]  # "aws", "aws-us-gov", "aws-cn"
    except Exception:
        return "aws"


def resolve_principal_arn(iam, principal: Attachment, account_id: str, partition: str) -> Optional[str]:
    """
    Resolve a principal's ARN (User/Role/Group).
    Try GetUser/GetRole/GetGroup first. If denied, construct best-effort ARN.
    """
    try:
        if principal.type == "Role":
            role = iam.get_role(RoleName=principal.name)["Role"]
            return role.get("Arn")
        if principal.type == "User":
            user = iam.get_user(UserName=principal.name)["User"]
            return user.get("Arn")
        if principal.type == "Group":
            grp = iam.get_group(GroupName=principal.name)["Group"]
            arn = grp.get("Arn")
            if arn:
                return arn
    except ClientError:
        pass
    # Construct a best-effort ARN (typical formats)
    if principal.type == "Role":
        return f"arn:{partition}:iam::{account_id}:role/{principal.name}"
    if principal.type == "User":
        return f"arn:{partition}:iam::{account_id}:user/{principal.name}"
    if principal.type == "Group":
        return f"arn:{partition}:iam::{account_id}:group/{principal.name}"
    return None

# ------------------------- IAM enumeration -------------------------
def list_policies(iam, include_aws_managed: bool) -> Iterable[Dict[str, Any]]:
    scopes = ["Local"] + (["AWS"] if include_aws_managed else [])
    for scope in scopes:
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope=scope):
            for p in page.get("Policies", []):
                yield p


def list_entities_for_policy(iam, policy_arn: str) -> Dict[str, List[Attachment]]:
    """
    Returns entity attachments for a managed policy.
    NOTE: list_entities_for_policy does not include ARNs for entities, so we only
    return names here and resolve ARNs later when needed.
    """
    out: Dict[str, List[Attachment]] = {"User": [], "Role": [], "Group": []}
    paginator = iam.get_paginator("list_entities_for_policy")
    for page in paginator.paginate(PolicyArn=policy_arn):
        for u in page.get("PolicyUsers", []):
            out["User"].append(Attachment("User", u["UserName"], arn=None))
        for r in page.get("PolicyRoles", []):
            out["Role"].append(Attachment("Role", r["RoleName"], arn=None))
        for g in page.get("PolicyGroups", []):
            out["Group"].append(Attachment("Group", g["GroupName"], arn=None))
    return out


def get_role_trust(iam, role_name: str) -> Dict[str, Any]:
    role = iam.get_role(RoleName=role_name)["Role"]
    return role.get("AssumeRolePolicyDocument", {})

# ------------------------- simulation & analysis -------------------------
def simulate_principal_actions(iam, arn: str, actions: List[str], resources: Optional[List[str]] = None) -> List[str]:
    """Return list of actions from `actions` that evaluate as allowed for the given principal."""
    allowed: List[str] = []
    chunk = 100  # API limit
    for i in range(0, len(actions), chunk):
        part = actions[i:i+chunk]
        resp = iam.simulate_principal_policy(
            PolicySourceArn=arn,
            ActionNames=part,
            ResourceArns=resources or ["*"],
        )
        for e in resp.get("EvaluationResults", []):
            if e.get("EvalDecision", "").lower() == "allowed":
                allowed.append(e.get("EvalActionName"))
    return allowed


def check_privesc(allowed_actions: Iterable[str]) -> List[str]:
    asetrule_actions = rule if isinstance(rule, list) else rule.get("actions", [])
        if all(a.lower() in aset for a in rule_actions):
            rule_name = ", ".join(rule_actions) if isinstance(rule, list) else rule.get("name", ", ".join(rule_actions))
            hits.append(rule_name
    for rule in PRIVESC_RULES:
        if all(a.lower() in aset for a in rule["actions"]):
            hits.append(rule["name"])
    return hits

# ------------------------- core audit -------------------------
def audit_policy_document(policy_doc: Dict[str, Any], threshold: int) -> Dict[str, Any]:
    """Return quick risk summary for a single policy document (no attachments)."""
    stmts = ensure_list(policy_doc.get("Statement") or [])
    wildcard_hits: List[Dict[str, Any]] = []
    many_action_hits: List[Dict[str, Any]] = []

    for stmt in stmts:
        actions, not_actions, resources, effect, cond = normalize_statement(stmt)
        explicit_denies = 1 if effect == "Deny" else 0
        if is_unrestricted(actions, resources, effect, cond):
            wildcard_hits.append({
                "statement": stmt,
                "conditions": cond,
                "explicit_denies": explicit_denies,
            })
            continue
        if actions and effect == "Allow":
            cnt = count_unique_actions(actions)
            if cnt >= threshold:
                many_action_hits.append({
                    "statement": stmt,
                    "count": cnt,
                    "conditions": cond,
                    "explicit_denies": explicit_denies,
                })

    return {"wildcard": wildcard_hits, "many_actions": many_action_hits}


def analyze_cross_account_exposure(trust_doc: Dict[str, Any], self_acct: str) -> str:
    """Rough classifier for role trust policies: public / external-account / internal."""
    principals: List[str] = []
    for stmt in ensure_list(trust_doc.get("Statement") or []):
        principal = stmt.get("Principal")
        if isinstance(principal, dict):
            for v in principal.values():
                principals += ensure_list(v)
        elif isinstance(principal, str):
            principals.append(principal)
    principals = [str(p) for p in principals]
    if any(p == "*" for p in principals):
        return "public"
    acct_ids: Set[str] = set()
    for p in principals:
        if p.startswith("arn:aws:iam::") or p.startswith("arn:aws-us-gov:iam::") or p.startswith("arn:aws-cn:iam::"):
            try:
                acct_ids.add(p.split("::")[1].split(":")[0])
            except Exception:
                pass
    if any(a != self_acct for a in acct_ids):
        return "external-account"
    return "internal"


def severity_from_factors(
    is_wildcard: bool,
    no_mfa: bool = False,
    stale_creds: bool = False,
) -> float:
    """
    Compose severity with opinionated bumps:
    - Keep normalized 0–100.
    - Internal + (sensitive or wildcard) should not sink to medium; raise floor.
    - Privilege escalation adds a kicker.
    """
    impact = 9.5 if is_wildcard else min(9.0, 4 + action_count / 10)
    exposure_map = {"public": 10, "external-account": 8, "internal": 5}
    exposure_score = exposure_map.get(exposure, 5)
    likelihood = 6.5 - (2.0 if has_conditions else 0.0)

    base = score_finding(impact, likelihood, exposure_score)

    # Internal but clearly dangerous? Lift it.
    if exposure == "internal" and (sensitive or is_wildcard):
        base = max(base, 45.0)  # floor into high-ish territory
        base += 5.0             # small nudge

    if privesc_hits:
        base += 10.0
    
    if no_mfa:
        base += 15.0  # MFA absence is critical
    
    if stale_creds:
        base -= 10.0  # Unused creds are less likely to be exploited

    return round(min(base, 100.0), 1)

def generate_remediation(finding_type: str, detail: str, principal_name: Optional[str] = None) -> str:
    """Generate actionable remediation advice based on finding type."""
    remediations = {
        "wildcard": f"Replace wildcard permissions with least-privilege grants. Use AWS Access Analyzer to identify actually-used actions, then create a scoped-down policy.",
        "many-actions": f"Review the {detail} actions and remove unused permissions. Consider splitting into multiple focused policies.",
        "effective-access": "Review simulated permissions and remove unnecessary sensitive actions. Apply conditions to restrict usage.",
        "privesc": "Remove privilege escalation vectors immediately. Ensure no principal can modify their own permissions or assume higher-privilege roles without approval.",
        "no-mfa": f"Enable MFA for user '{principal_name or 'this user'}': aws iam enable-mfa-device --user-name {principal_name or '<USER>'}",
        "stale-credentials": f"Deactivate or delete unused credentials for '{principal_name or 'this user'}': aws iam delete-access-key --user-name {principal_name or '<USER>'} --access-key-id <KEY_ID>",
        "inline-policy": f"Convert inline policy to a managed policy for better governance and reusability: aws iam create-policy then attach with put-*-policy commands.",
        "insufficient-permissions": "Grant the audit role permission to read this policy/attachment, or accept reduced visibility.",
    }
    return remediations.get(finding_type, "Review and apply least-privilege principles.")

def check_mfa_and_stale_creds(iam, stale_days: int) -> Tuple[Dict[str, bool], Dict[str, int]]:
    """
    Returns (mfa_status, days_since_password_use) for all users.
    Uses credential report for efficiency.
    """
    mfa_status: Dict[str, bool] = {}
    days_unused: Dict[str, int] = {}
    
    try:
        # Generate credential report (may take a moment)
        iam.generate_credential_report()
        import time
        for _ in range(10):
            try:
                resp = iam.get_credential_report()
                break
            except ClientError as e:
                if "ReportInProgress" in str(e):
                    time.sleep(2)
                else:
                    raise
    
    # NEW: Check MFA and stale credentials
    mfa_status: Dict[str, bool] = {}
    stale_creds: Dict[str, int] = {}
    if check_mfa or check_stale:
        mfa_status, stale_creds = check_mfa_and_stale_creds(iam, stale_days)
    
    # NEW: Check inline policies
    inline_policies: Dict[str, List[str]] = {}
    if check_inline:
        inline_policies = check_inline_policies(iam)
        else:
            return mfa_status, days_unused
        
        # Parse CSV report
        import csv as csv_mod
        from io import StringIO
        from datetime import datetime, timezone
        
        report = resp["Content"].decode("utf-8")
        reader = csv_mod.DictReader(StringIO(report))
        
        for row in reader:
            user = row.get("user", "")
            if user == "<root_account>":
                continue
            
            # MFA status
            mfa_active = row.get("mfa_active", "false").lower() == "true"
            mfa_status[user] = mfa_active
            
            # Password last used
            password_last_used = row.get("password_last_used", "N/A")
            if password_last_used not in ["N/A", "no_information"]:
                try:
                    last_used = datetime.fromisoformat(password_last_used.replace("Z", "+00:00"))
                    days = (datetime.now(timezone.utc) - last_used).days
                    if days >= stale_days:
                        days_unused[user] = days
                except Exception:
                    pass
            
            # Access key last used (check both keys)
            for key_num in ["1", "2"]:
                key_last_used = row.get(f"access_key_{key_num}_last_used_date", "N/A")
                if key_last_used not in ["N/A", "no_information"]:
                    try:
                        last_used = datetime.fromisoformat(key_last_used.replace("Z", "+00:00"))
                        days = (datetime.now(timezone.utc) - last_used).days
                        if days >= stale_days:
                            days_unused[user] = min(days_unused.get(user, 999), days)
                    except Exception:
                        pass
    except ClientError:
        pass  # Credential report may not be available
    
    return mfa_status, days_unused
# Check if principal has MFA/stale creds issues
            has_mfa = True
            is_stale = False
            if principal and principal.type == "User":
                has_mfa = mfa_status.get(principal.name, True)
                is_stale = principal.name in stale_creds
                if principal.name in stale_creds:
                    f.days_since_use = stale_creds[principal.name]
            
            f.severity_score = severity_from_factors(
                is_wildcard=(risk_type == "wildcard"),
                action_count=(f.action_count or 0),
                exposure=f.exposure,
                has_conditions=has_conditions,
                sensitive=sensitive_flag,
                privesc_hits=privesc_hits,
                no_mfa=(not has_mfa),
                stale_creds=is_stale,
            )
            f.remediation = generate_remediation(risk_type, detail, principal.name if principal else None)
            f.compliance_frameworks = map_to_compliance(risk_type, has_mfanator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                user_name = user["UserName"]
                pol_paginator = iam.get_paginator("list_user_policies")
                policies = []
                for pol_page in pol_paginator.paginate(UserName=user_name):
                    policies.extend(pol_page.get("PolicyNames", []))
                if policies:
                    inline_map[f"User:{user_name}"] = policies
        
        # Roles with inline policies
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]
                pol_paginator = iam.get_paginator("list_role_policies")
                policies = []
                for pol_page in pol_paginator.paginate(RoleName=role_name):
                    policies.extend(pol_page.get("PolicyNames", []))
                if policies:
                    inline_map[f"Role:{role_name}"] = policies
        
        # Groups with inline policies
        paginator = iam.get_paginator("list_groups")
        for page in paginator.paginate():
            for group in page.get("Groups", []):
                group_name = group["GroupName"]
                pol_paginator = iam.get_paginator("list_group_policies")
                policies = []
                for pol_page in pol_paginator.paginate(GroupName=group_name):
                    policies.extend(pol_page.get("PolicyNames", []))
                if policies:
                    inline_map[f"Group:{group_name}"] = policies
    except ClientError:
        pass
    
    return inline_map

def run_audit(
    profile: Optional[str], region: Optional[str], assume_role_arn: Optional[str], threshold: int,
    include_aws_managed: bool, simulate: bool, check_privesc_flag: bool, check_cross_acct: bool,
    services: List[str], max_workers: int, sensitive_actions_set: set[str], 
    check_mfa: bool = False, check_stale: bool = False, stale_days: int = DEFAULT_STALE_DAYS,
    check_inline: bool = False
        "wildcard": ["CIS AWS 1.22", "PCI-DSS 7.1.2", "NIST 800-53 AC-6"],
        "many-actions": ["CIS AWS 1.22", "PCI-DSS 7.1.2"],
        "privesc": ["CIS AWS 1.16", "PCI-DSS 7.2", "NIST 800-53 AC-6"],
        "no-mfa": ["CIS AWS 1.2", "CIS AWS 1.3", "PCI-DSS 8.3"],
        "stale-credentials": ["CIS AWS 1.3", "PCI-DSS 8.1.4"],
        "inline-policy": ["AWS Well-Architected SEC02-BP02"],
    }
    frameworks.extend(mapping.get(finding_type, []))
    return frameworks if frameworks else []ll nudge

    if privesc_hits:
        base += 10.0

    return round(min(base, 100.0), 1)

def make_insufficient_perm_finding(account_id: str, policy_arn: str, policy_name: str, operation: str, err: Exception) -> Finding:
    code = None
    msg = None
    try:
        code = err.response.get("Error", {}).get("Code")       # type: ignore[attr-defined]
        msg  = err.response.get("Error", {}).get("Message")    # type: ignore[attr-defined]
    except Exception:
        pass
    detail = f"{operation} failed: {code or type(err).__name__}: {msg or str(err)}"
    return Finding(
        account_id=account_id,
        policy_arn=policy_arn,
        policy_name=policy_name,
        attachment_type="managed",
        risk_type="insufficient-permissions",
        detail=detail,
        severity_score=0.0,
    )

def run_audit(
    profile: Optional[str], region: Optional[str], assume_role_arn: Optional[str], threshold: int,
    include_aws_managed: bool, simulate: bool, check_privesc_flag: bool, check_cross_acct: bool,
    services: List[str], max_workers: int, sensitive_actions_set: set[str]
) -> List[Finding]:
    base_session = make_session(profile, region)
    session = assume_role_if_needed(base_session, assume_role_arn)
    cfg = BotoConfig(retries={"max_attempts": 10, "mode": "standard"})
    iam = session.client("iam", config=cfg)

    # Resolve account id and partition
    sts = session.client("sts")
    ident = sts.get_caller_identity()
    account_id = ident.get("Account")
    caller_arn = ident.get("Arn")
    partition = get_partition_from_sts_arn(caller_arn)

    sensitive_actions_for_sim = [a for a in SENSITIVE_ACTIONS_SEED if a.split(":")[0] in services or a == "*"]

    findings: List[Finding] = []
    errors: List[str] = []

    policy_iter = list_policies(iam, include_aws_managed)

    def process_policy(p: Dict[str, Any]) -> List[Finding]:
        res: List[Finding] = []
    
    # NEW: Add MFA findings
    if check_mfa:
        for user, has_mfa in mfa_status.items():
            if not has_mfa:
                f = Finding(
                    account_id=account_id,
                    policy_arn="n/a",
                    policy_name="n/a",
                    attachment_type="n/a",
                    principal_type="User",
                    principal_name=user,
                    principal_arn=f"arn:{partition}:iam::{account_id}:user/{user}",
                    risk_type="no-mfa",
                    detail=f"User '{user}' does not have MFA enabled",
                    severity_score=severity_from_factors(False, 0, "internal", False, no_mfa=True),
                    remediation=generate_remediation("no-mfa", "", user),
                    compliance_frameworks=map_to_compliance("no-mfa"),
                )
                findings.append(f)
    
    # NEW: Add stale credential findings
    if check_stale:
        for user, days in stale_creds.items():
            f = Finding(
                account_id=account_id,
                policy_arn="n/a",
                policy_name="n/a",
                attachment_type="n/a",
                principal_type="User",
                principal_name=user,
                principal_arn=f"arn:{partition}:iam::{account_id}:user/{user}",
                risk_type="stale-credentials",
                detail=f"User '{user}' has not used credentials in {days} days",
                days_since_use=days,
                severity_score=severity_from_factors(False, 0, "internal", False, stale_creds=True),
                remediation=generate_remediation("stale-credentials", "", user),
                compliance_frameworks=map_to_compliance("stale-credentials"),
            )
            findings.append(f)
    
    # NEW: Add inline policy findings
    if check_inline:
        for principal_key, policy_names in inline_policies.items():
            ptype, pname = principal_key.split(":", 1)
            for pol_name in policy_names:
                f = Finding(
                    account_id=account_id,
                    policy_arn="n/a",
                    policy_name=pol_name,
                    attachment_type="inline",
                    principal_type=ptype,,
        "remediation","compliance_frameworks","days_since_use"
    ]
    from io import StringIO
    buf = StringIO()
    w = csv.writer(buf)
    w.writerow(headers)
    for f in findings:
        w.writerow([
            f.account_id, f.policy_arn, f.policy_name, f.attachment_type, f.principal_type, f.principal_name, f.principal_arn,
            f.risk_type, f.detail, f.action_count, json.dumps(f.conditions or {}), f.explicit_denies, f.exposure,
            ";".join(f.allowed_examples or []) if f.allowed_examples else "", ";".join(f.privesc_hits or []) if f.privesc_hits else "",
            f.severity_score, f.remediation or "", ";".join(f.compliance_frameworks or []) if f.compliance_frameworks else "",
            f.days_since_use or ""icyName"]

        # Fetch default policy version with per-operation error capture
        try:
            pol = iam.get_policy(PolicyArn=policy_arn)["Policy"]
        except ClientError as e:
            errors.append(f"iam:GetPolicy failed for {policy_arn}: {e}")
            res.append(make_insufficient_perm_finding(account_id, policy_arn, policy_name, "iam:GetPolicy", e))
            return res

        try:
            ver = iam.get_policy_version(PolicyArn=policy_arn, VersionId=pol["DefaultVersionId"])  # type: ignore
            policy_doc = ver["PolicyVersion"]["Document"]
            quick = audit_policy_document(policy_doc, threshold)
        except ClientError as e:
            errors.append(f"iam:GetPolicyVersion failed for {policy_arn}: {e}")
            res.append(make_insufficient_perm_finding(account_id, policy_arn, policy_name, "iam:GetPolicyVersion", e))
            return res

        # Attachments
        try:
            attached = list_entities_for_policy(iam, policy_arn)
        except ClientError as e:
            errors.append(f"iam:ListEntitiesForPolicy failed for {policy_arn}: {e}")
            res.append(make_insufficient_perm_finding(account_id, policy_arn, policy_name, "iam:ListEntitiesForPolicy", e))
            attached = {"User": [], "Role": [], "Group": []}

        # Helper to build a finding; resolve ARN if missing
        def mk_find(prcheck-mfa", action="store_true", help="Check for users without MFA enabled")
    p.add_argument("--check-stale", action="store_true", help="Detect unused/stale credentials")
    p.add_argument("--stale-days", type=int, default=DEFAULT_STALE_DAYS, help="Days of inactivity to flag credentials as stale (default: 90)")
    p.add_argument("--check-inline", action="store_true", help="Flag inline policies (best practice: use managed policies)")
    p.add_argument("--incipal: Optional[Attachment], risk_type: str, detail: str, action_count: Optional[int],
                    conditions: Optional[Dict[str, Any]], exposure: str, explicit_denies: int,
                    sensitive_flag: bool = False, privesc_hits: Optional[List[str]] = None) -> Finding:
            principal_arn = None
            if principal:
                principal_arn = principal.arn or resolve_principal_arn(iam, principal, account_id, partition)
            f = Finding(
                account_id=account_id,
                policy_arn=policy_arn,
                policy_name=policy_name,
                attachment_type="managed",
                principal_type=(principal.type if principal else None),
                principal_name=(principal.name if principal else None),
                principal_arn=principal_arn,
                risk_type=risk_type,
                detail=detail,
                action_count=action_count,
                conditions=conditions,
                explicit_denies=explicit_denies,
                exposure=exposure,
                privesc_hits=privesc_hits,
            )
            has_conditions = bool(f.conditions)
            f.severity_score = severity_from_factors(
        check_mfa=args.check_mfa,
        check_stale=args.check_stale,
        stale_days=args.stale_days,
        check_inline=args.check_inline,
                is_wildcard=(risk_type == "wildcard"),
                action_count=(f.action_count or 0),
                exposure=f.exposure,
                has_conditions=has_conditions,
                sensitive=sensitive_flag,
                privesc_hits=privesc_hits,
            )
            return f

        # Wildcards
        for hit in quick["wildcard"]:
            principals = attached["User"] + attached["Role"] + attached["Group"]
            if not principals:
                principals = [None]  # unattached policy still worth reporting
            for principal in principals:
                exposure = "internal"
                if check_cross_acct and principal and principal.type == "Role":
                    try:
                        trust = get_role_trust(iam, principal.name)
                        exposure = analyze_cross_account_exposure(trust, account_id)
                    except ClientError as e:
                        errors.append(f"iam:GetRole failed for {policy_arn}: {e}")
                        res.append(make_insufficient_perm_finding(account_id, policy_arn, policy_name, "iam:GetRole", e))
                # wildcard is inherently sensitive
                f = mk_find(
                    principal,
                    "wildcard",
                    "Effect:Allow with Action:* (or service:*) and Resource:* with no conditions",
                    None,
                    hit.get("conditions"),
                    exposure,
                    hit.get("explicit_denies", 0),
                    sensitive_flag=True,
                )
                res.append(f)

        # Many-actions
        for hit in quick["many_actions"]:
            principals = attached["User"] + attached["Role"] + attached["Group"]
            if not principals:
                principals = [None]
            # Pull the statement to assess sensitivity
            stmt = hit.get("statement", {})
            actions, _, resources, _, _ = normalize_statement(stmt)
            sens_flag = has_sensitive(actions, sensitive_actions_set)

            for principal in principals:
                exposure = "internal"
                if check_cross_acct and principal and principal.type == "Role":
                    try:
                        trust = get_role_trust(iam, principal.name)
                        exposure = analyze_cross_account_exposure(trust, account_id)
                    except ClientError as e:
                        errors.append(f"iam:GetRole failed for {policy_arn}: {e}")
                        res.append(make_insufficient_perm_finding(account_id, policy_arn, policy_name, "iam:GetRole", e))
                f = mk_find(
                    principal,
                    "many-actions",
                    "Effect:Allow with many distinct actions (≥ threshold)",
                    hit.get("count"),
                    hit.get("conditions"),
                    exposure,
                    hit.get("explicit_denies", 0),
                    sensitive_flag=sens_flag,
                )
                res.append(f)

        # Optional simulation & privesc per principal
        if simulate or check_privesc_flag:
            principals = attached["User"] + attached["Role"] + attached["Group"]
            for principal in principals:
                if not principal:
                    continue
                arn = principal.arn or resolve_principal_arn(iam, principal, account_id, partition)
                if not arn:
                    res.append(Finding(
                        account_id=account_id,
                        policy_arn=policy_arn,
                        policy_name=policy_name,
                        attachment_type="managed",
                        principal_type=principal.type,
                        principal_name=principal.name,
                        principal_arn=None,
                        risk_type="insufficient-permissions",
                        detail=f"Could not resolve ARN for {principal.type}:{principal.name} to run SimulatePrincipalPolicy",
                        severity_score=0.0,
                    ))
                    continue
                try:
                    allowed = simulate_principal_actions(iam, arn, sensitive_actions_for_sim)
                except ClientError as e:
                    errors.append(f"SimulatePrincipalPolicy failed for {arn}: {e}")
                    res.append(make_insufficient_perm_finding(account_id, policy_arn, policy_name, "iam:SimulatePrincipalPolicy", e))
                    allowed = []
                if allowed:
                    pr_hits = check_privesc(allowed) if check_privesc_flag else []
                    sens = any(a.lower() in sensitive_actions_set or a.endswith(":*") for a in allowed)
                    exposure = "internal"
                    if check_cross_acct and principal.type == "Role":
                        try:
                            trust = get_role_trust(iam, principal.name)
                            exposure = analyze_cross_account_exposure(trust, account_id)
                        except ClientError as e:
                            errors.append(f"iam:GetRole failed for {policy_arn}: {e}")
                            res.append(make_insufficient_perm_finding(account_id, policy_arn, policy_name, "iam:GetRole", e))
                    f = mk_find(
                        principal,
                        "effective-access",
                        "Principal is allowed selected sensitive actions (simulation)",
                        len(allowed),
                        None,
                        exposure,
                        0,
                        sensitive_flag=sens,
                        privesc_hits=pr_hits or None,
                    )
                    f.allowed_examples = sorted(allowed)[:25]
                    res.append(f)

        return res

    with futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for chunk_findings in ex.map(process_policy, policy_iter, chunksize=5):
            findings.extend(chunk_findings)

    return findings

# ------------------------- output -------------------------
def to_table(findings: List[Finding]) -> str:
    totals = defaultdict(int)
    for f in findings:
        totals[f.risk_type] += 1

    headers = [
        "severity", "risk_type", "principal", "policy", "attachment", "exposure", "actions", "privesc", "detail",
    ]
    rows = []
    for f in sorted(findings, key=lambda x: (-(x.severity_score or 0), x.risk_type)):
        principal = f"{f.principal_type or '-'}:{f.principal_name or '-'}"
        policy = f"{f.policy_name or '-'}"
        rows.append([
            f.severity_score,
            f.risk_type,
            principal,
            policy,
            f.attachment_type,
            f.exposure,
            f.action_count or (len(f.allowed_examples or []) if f.allowed_examples else 0),
            ",".join(f.privesc_hits or []) if f.privesc_hits else "",
            (f.detail[:80] + "…") if len(f.detail) > 80 else f.detail,
        ])
    colw = [max(len(str(c)) for c in [h] + [r[i] for r in rows]) for i, h in enumerate(headers)]
    line = "+" + "+".join("-" * (w + 2) for w in colw) + "+"
    out = []
    if totals:
        summary_items = ", ".join(f"{k}={v}" for k, v in sorted(totals.items()))
        out.append(f"Findings summary: {summary_items}")
    out.append(line)
    out.append("| " + " | ".join(str(h).ljust(colw[i]) for i, h in enumerate(headers)) + " |")
    out.append(line)
    for r in rows:
        out.append("| " + " | ".join(str(r[i]).ljust(colw[i]) for i in range(len(headers))) + " |")
    out.append(line)
    return "\n".join(out)


def to_json(findings: List[Finding]) -> str:
    return json.dumps([asdict(f) for f in findings], indent=2, default=str)


def to_csv(findings: List[Finding]) -> str:
    headers = [
        "account_id","policy_arn","policy_name","attachment_type","principal_type","principal_name","principal_arn",
        "risk_type","detail","action_count","conditions","explicit_denies","exposure","allowed_examples","privesc_hits","severity_score"
    ]
    from io import StringIO
    buf = StringIO()
    w = csv.writer(buf)
    w.writerow(headers)
    for f in findings:
        w.writerow([
            f.account_id, f.policy_arn, f.policy_name, f.attachment_type, f.principal_type, f.principal_name, f.principal_arn,
            f.risk_type, f.detail, f.action_count, json.dumps(f.conditions or {}), f.explicit_denies, f.exposure,
            ";".join(f.allowed_examples or []) if f.allowed_examples else "", ";".join(f.privesc_hits or []) if f.privesc_hits else "",
            f.severity_score,
        ])
    return buf.getvalue()


def write_output(findings: List[Finding], fmt: str, output: Optional[str]):
    if fmt == "json":
        data = to_json(findings)
    elif fmt == "csv":
        data = to_csv(findings)
    elif fmt == "table":
        data = to_table(findings)
    else:
        raise SystemExit(f"Unsupported format: {fmt}")

    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(data)
        print(f"Wrote {fmt.upper()} to {output}")
    else:
        print(data)

# ------------------------- CLI -------------------------
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Audit IAM policy permissiveness with attachments, simulation and scoring")
    p.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD, help="Action count threshold for many-actions")
    p.add_argument("--include-aws-managed", action="store_true", help="Include AWS-managed policies")
    p.add_argument("--simulate", action="store_true", help="Simulate sensitive actions per principal")
    p.add_argument("--check-privesc", action="store_true", help="Detect privilege escalation patterns (requires --simulate for best results)")
    p.add_argument("--check-cross-account", action="store_true", help="Analyze role trust policies for external/public exposure")
    p.add_argument("--services", default=",".join(DEFAULT_SENSITIVE_SERVICES), help="Comma-separated services to include in sensitive action simulation (e.g., s3,iam,kms)")
    p.add_argument("--format", choices=["json","csv","table"], default="table", help="Output format")
    p.add_argument("--output", help="Path to write output; prints to stdout if omitted")
    p.add_argument("--profile", help="AWS profile name")
    p.add_argument("--region", help="AWS region (for STS/clients)")
    p.add_argument("--assume-role-arn", help="Role ARN to assume before scanning")
    p.add_argument("--max-workers", type=int, default=8, help="Concurrency for policy processing")
    p.add_argument("--sensitive-actions-file", help="Path to JSON file (array of actions) to treat as sensitive")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    services = [s.strip().lower() for s in args.services.split(",") if s.strip()]
    sensitive_set = load_sensitive_actions(args.sensitive_actions_file)

    findings = run_audit(
        profile=args.profile,
        region=args.region,
        assume_role_arn=args.assume_role_arn,
        threshold=args.threshold,
        include_aws_managed=args.include_aws_managed,
        simulate=args.simulate,
        check_privesc_flag=args.check_privesc,
        check_cross_acct=args.check_cross_account,
        services=services,
        max_workers=args.max_workers,
        sensitive_actions_set=sensitive_set,
    )

    write_output(findings, args.format, args.output)
    print("Scan complete.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
