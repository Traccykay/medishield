# `src/Reporting/`

Role-scoped aggregate reporting lives here. Reports return operational counts
only and deliberately exclude names, contact details, diagnoses, laboratory
result text, medication text, and other clinical contents. Every query binds the
current authenticated user identifier so one workforce member cannot inspect
another member's activity through the reporting page.
