/**
 * @name Browser messages with wildcard destination
 * @description Review cross-origin messaging and use an explicit target origin.
 * @kind problem
 * @problem.severity warning
 * @id actionhound/js-wildcard-message
 */
import javascript

from MethodCallExpr call, StringLiteral target
where call.getMethodName() = "postMessage" and target = call.getArgument(1) and target.getValue() = "*"
select call, "Use an explicit target origin for browser messages."
