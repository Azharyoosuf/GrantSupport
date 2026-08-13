#!/usr/bin/env python3
"""
HISTORICAL ARCHIVE ONLY — DO NOT RE-RUN
---------------------------------------
This script is a one-time historical record of how the GrantSupport codebase
was initially extracted from TenantPro (go-backend).
It is NOT meant to be re-run and does NOT indicate any ongoing runtime
or build-time dependency on TenantPro. GrantSupport is a 100% standalone product.
"""

import os
import shutil
import re

SOURCE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "go-backend"))
TARGET_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

FILES_TO_COPY = [
    # Schemas
    ("ent/schema/supportgrant.go", "ent/schema/supportgrant.go"),
    ("ent/schema/auditevent.go", "ent/schema/auditevent.go"),
    
    # Domain & Security (Ed25519 + RS256 + 10 Pillars)
    ("pkg/domain/support_grant.go", "pkg/domain/support_grant.go"),
    ("pkg/security/events.go", "pkg/security/events.go"),
    ("pkg/security/jwt.go", "pkg/security/jwt.go"),
    ("pkg/security/keys.go", "pkg/security/keys.go"),
    
    # Repository Layer
    ("pkg/repository/support_grant_repository.go", "pkg/repository/support_grant_repository.go"),
    ("pkg/repository/security_audit_repository.go", "pkg/repository/security_audit_repository.go"),
    ("pkg/repository/base.go", "pkg/repository/base.go"),
    
    # Service Layer
    ("pkg/service/grant_support_service.go", "pkg/service/grant_support_service.go"),
    
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
    print("Historical Extraction Archive - Not meant to be executed.")

if __name__ == "__main__":
    main()
