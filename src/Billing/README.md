# `src/Billing` — visit-linked billing

`BillingService` authorizes billing actions and resolves each selected service or
medication from the server-side `ClinicalCatalog`. `BillingRepository` stores the
description and integer-KES unit price on every charge, so an invoice stays
historically correct if the catalogue changes later.

Receptionists may manage only visits that they created; administrators may manage
all visits. Patient users receive a read-only view limited to the patient record
linked to their own login.
