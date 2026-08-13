---
description: 
---

Act as a senior backend engineer.

---

## 🎯 GOAL

Implement the feature STRICTLY based on the approved plan.

---

## 🔒 STRICT RULES

* Follow: Route → Controller → Service → Repository
* NO direct Prisma usage outside repository
* MUST enforce multi-tenant (institution_id)
* MUST use explicit select (NO SELECT *)
* MUST include validation (Zod)
* MUST follow API response format:

{
success: boolean,
message: string,
data: object | null,
meta?: object
}

---

## ⚙️ GENERATE

1. Zod validation schema
2. Controller (thin)
3. Service (business logic)
4. Repository (DB layer)
5. Route definition

---

## 🧪 ALSO INCLUDE

* Example request
* Example response
* Notes for testing

---

## 🚫 DO NOT

* Skip validation
* Break architecture rules
* Add unnecessary features
* Access Prisma outside repository

---

## ⚠️ ERROR HANDLING

* Use structured errors
* Do NOT return raw errors
* Ensure consistent error format

---

## 🔒 MULTI-TENANT RULE

institution_id must:

* NEVER come from request body
* ALWAYS come from auth context

---

Implement ONLY what is in plan.
