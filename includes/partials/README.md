# `includes/partials/` - Include-only view fragments

These PHP templates are rendered only by authenticated application controllers.
They live outside Apache's `public` document root so they cannot be executed as
standalone HTTP endpoints.

Templates inherit their variables and escaped-output helpers from the including
controller. They must not perform authorization, database access, or state
changes; those responsibilities remain in the controller and service layers.
