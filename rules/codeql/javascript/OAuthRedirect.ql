/**
 * @name Request-controlled OAuth redirect URI
 * @description The OAuth redirect URI reaches a redirect without an explicit registered URI lookup.
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id actionhound/js/oauth-redirect
 * @tags security
 *       external/cwe/cwe-601
 */

import javascript

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::PropRead parameter |
      source = parameter and
      parameter.getPropertyName() = "redirect_uri" and
      parameter.getBase().(DataFlow::PropRead).getPropertyName() = ["query", "body"]
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode redirect |
      redirect.getMethodName() = "redirect" and sink = redirect.getAnArgument()
    )
  }
}

module Flow = TaintTracking::Global<Config>;

from DataFlow::Node source, DataFlow::Node sink
where Flow::flow(source, sink)
select sink, "Resolve this redirect through an exact registered URI allowlist."
