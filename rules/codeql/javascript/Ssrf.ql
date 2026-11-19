/**
 * @name Remote input reaches a JavaScript HTTP destination
 * @description Remote user input controls an outbound HTTP request destination.
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id actionhound/js/ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import javascript
import semmle.javascript.security.dataflow.RemoteFlowSources

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    sink = DataFlow::globalVarRef("fetch").getACall().getArgument(0)
    or
    sink = DataFlow::moduleMember("axios", ["get", "post", "put", "patch", "delete"])
        .getACall().getArgument(0)
  }
}

module Flow = TaintTracking::Global<Config>;

from DataFlow::Node source, DataFlow::Node sink
where Flow::flow(source, sink)
select sink, "Enforce an explicit destination policy before making this request."
