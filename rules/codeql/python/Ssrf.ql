/**
 * @name Remote input reaches a Python HTTP destination
 * @description Remote user input controls an outbound HTTP request destination.
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id actionhound/python/ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    exists(API::Node client, API::CallNode call |
      (
        client = API::moduleImport(["requests", "httpx"]).getMember(
          ["get", "post", "put", "patch", "delete", "head", "options"]
        )
        or
        client = API::moduleImport("urllib").getMember("request").getMember("urlopen")
      ) and
      call = client.getACall() and
      sink = [call.getArg(0), call.getArgByName("url")]
    )
  }
}

module Flow = TaintTracking::Global<Config>;

from DataFlow::Node source, DataFlow::Node sink
where Flow::flow(source, sink)
select sink, "Enforce an explicit destination policy before making this request."
