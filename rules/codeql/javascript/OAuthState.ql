/**
 * @name Passport OAuth2 strategy without explicit state protection
 * @description The inline OAuth2 strategy options do not enable session state verification.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id actionhound/js/oauth-state
 * @tags security
 *       external/cwe/cwe-352
 */

import javascript

from NewExpr strategy, ObjectExpr options
where
  strategy.getCalleeName() = "OAuth2Strategy" and
  options = strategy.getArgument(0) and
  options.getAProperty().getName() = "authorizationURL" and
  options.getAProperty().getName() = "tokenURL" and
  not exists(Property p |
    p = options.getAProperty() and
    (p.getName() = "store" or p.getName() = "state" and p.getInit().toString() = "true")
  )
select options, "Enable session-backed state validation for this OAuth2 strategy."
