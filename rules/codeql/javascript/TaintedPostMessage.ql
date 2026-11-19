/**
 * @name Request-controlled postMessage target origin
 * @description A request-controlled target origin can direct a message to an unintended origin.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id actionhound/js/tainted-postmessage
 * @tags security
 *       external/cwe/cwe-346
 */

import javascript
import semmle.javascript.security.dataflow.RemoteFlowSources

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode post |
      post.getMethodName() = "postMessage" and sink = post.getArgument(1)
    )
  }
}

module Flow = TaintTracking::Global<Config>;

from DataFlow::Node source, DataFlow::Node sink
where Flow::flow(source, sink)
select sink, "Use a trusted exact target origin for this message."
