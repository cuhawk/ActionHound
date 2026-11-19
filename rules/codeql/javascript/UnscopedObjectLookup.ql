/**
 * @name Request-controlled object lookup by ID
 * @description A route parameter reaches a lookup by object ID without tenant scope in the query.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id actionhound/js/unscoped-object-lookup
 * @tags security
 *       external/cwe/cwe-639
 */

import javascript

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.(DataFlow::PropRead).getBase().(DataFlow::PropRead).getPropertyName() = ["params", "query"]
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode lookup |
      lookup.getMethodName() = "findById" and sink = lookup.getArgument(0)
    )
  }
}

module Flow = TaintTracking::Global<Config>;

from DataFlow::Node source, DataFlow::Node sink
where Flow::flow(source, sink)
select sink, "Scope this lookup to the authorized tenant or enforce object authorization before use."
