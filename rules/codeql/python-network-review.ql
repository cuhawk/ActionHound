/**
 * @name HTTP destinations requiring review
 * @description Review variable destinations at common outbound HTTP call sites.
 * @kind problem
 * @problem.severity warning
 * @id actionhound/py-network-destination
 */
import python

from Call call, Attribute callee, Name receiver, Name destination
where
  callee = call.getFunc() and
  receiver = callee.getObject() and
  receiver.getId() in ["requests", "httpx"] and
  callee.getName() in ["get", "post"] and
  destination = call.getArg(0)
select call, "Check that the outbound URL is constrained to permitted destinations."
