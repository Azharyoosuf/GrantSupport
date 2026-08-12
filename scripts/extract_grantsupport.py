#!/usr/bin/env python3
"""
GrantSupport Extraction Script
Copies core GrantSupport files from TenantPro (go-backend) into standalone GrantSupport module.
"""

import os
import shutil
import re

SOURCE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "go-backend"))
TARGET_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

FILES_TO_COPY = [
    # Schemas
    ("ent/schema/supportgrant.go", "ent/schema/supportgrant.go"),
    ("ent/schema/auditevent.go", "ent/schema/auditevent.go"),
    ("ent/schema/apiusagelog.go", "ent/schema/apiusagelog.go"),
    
    # Domain & Security (Ed25519 + RS256 + 10 Pillars)
    ("pkg/domain/support_grant.go", "pkg/domain/support_grant.go"),
    ("pkg/security/events.go", "pkg/security/events.go"),
    ("pkg/security/jwt.go", "pkg/security/jwt.go"),
    ("pkg/security/keys.go", "pkg/security/keys.go"),
    
    # Repository Layer
    ("pkg/repository/support_grant_repository.go", "pkg/repository/support_grant_repository.go"),
    ("pkg/repository/security_audit_repository.go", "pkg/repository/security_audit_repository.go"),
    ("pkg/repository/api_usage_log_repository.go", "pkg/repository/api_usage_log_repository.go"),
    ("pkg/repository/base.go", "pkg/repository/base.go"),
    
    # Service Layer
    ("pkg/service/auth_service.go", "pkg/service/auth_service.go"),
    
    # Controller Layer
    ("pkg/controller/auth_support_controller.go", "pkg/controller/auth_support_controller.go"),
    ("pkg/controller/auth_dto.go", "pkg/controller/auth_dto.go"),
    ("pkg/controller/base_controller.go", "pkg/controller/base_controller.go"),
    
    # Middleware & Context Layer (Bulletproof 5-Layer Security + RBAC + Correlation)
    ("pkg/context/context.go", "pkg/context/context.go"),
    ("pkg/config/config.go", "pkg/config/config.go"),
    ("pkg/middleware/auth.go", "pkg/middleware/auth.go"),
    ("pkg/middleware/bulletproof_auth.go", "pkg/middleware/bulletproof_auth.go"),
    ("pkg/middleware/bulletproof_auth_test.go", "pkg/middleware/bulletproof_auth_test.go"),
    ("pkg/middleware/rbac.go", "pkg/middleware/rbac.go"),
    ("pkg/middleware/correlation.go", "pkg/middleware/correlation.go"),
    
    # Cache & Redlock Layer
    ("pkg/cache/valkey.go", "pkg/cache/valkey.go"),
]

def main():
    print("Starting GrantSupport Extraction...")
    print(f"Source: {SOURCE_DIR}")
    print(f"Target: {TARGET_DIR}")

    copied_count = 0
    for src_rel, dst_rel in FILES_TO_COPY:
        src_path = os.path.join(SOURCE_DIR, src_rel)
        dst_path = os.path.join(TARGET_DIR, dst_rel)

        if not os.path.exists(src_path):
            print(f"Warning: Source file missing: {src_path}")
            continue

        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
        shutil.copy2(src_path, dst_path)

        # Fix package imports from tenantpro -> grantsupport
        with open(dst_path, "r", encoding="utf-8") as f:
            content = f.read()

        content = content.replace("tenantpro/", "grantsupport/")
        
        with open(dst_path, "w", encoding="utf-8") as f:
            f.write(content)

        print(f"Copied & Updated: {dst_rel}")
        copied_count += 1

    # Create standalone go.mod if not exists
    go_mod_path = os.path.join(TARGET_DIR, "go.mod")
    if not os.path.exists(go_mod_path):
        go_mod_content = """module grantsupport

go 1.22.0
"""
        with open(go_mod_path, "w", encoding="utf-8") as f:
            f.write(go_mod_content)
        print("Created standalone go.mod")

    print(f"\nExtraction Complete! {copied_count} files copied into {TARGET_DIR}")

if __name__ == "__main__":
    main()
