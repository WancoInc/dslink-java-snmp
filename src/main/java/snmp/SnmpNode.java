package snmp;

import java.io.IOException;

import org.dsa.iot.dslink.node.Node;
import org.dsa.iot.dslink.node.NodeBuilder;
import org.dsa.iot.dslink.node.Permission;
import org.dsa.iot.dslink.node.Writable;
import org.dsa.iot.dslink.node.actions.Action;
import org.dsa.iot.dslink.node.actions.ActionResult;
import org.dsa.iot.dslink.node.actions.Parameter;
import org.dsa.iot.dslink.node.value.Value;
import org.dsa.iot.dslink.node.value.ValuePair;
import org.dsa.iot.dslink.node.value.ValueType;
import org.dsa.iot.dslink.util.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.smi.AbstractVariable;
import org.snmp4j.smi.AssignableFromString;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.SMIConstants;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;
import org.dsa.iot.dslink.util.handler.Handler;

import snmp.SnmpLink.SnmpVersion;

public class SnmpNode {
	static private final Logger LOGGER;

	protected Node node;
	protected SnmpLink link;
	protected Snmp snmp;
	protected AgentNode root;

	SnmpNode(SnmpLink slink, Node mynode) {
		link = slink;
		node = mynode;
		node.setAttribute("restoreType", new Value("folder"));
		this.snmp = link.snmp;

		Action act = new Action(Permission.READ, new GetHandler());
		act.addParameter(new Parameter("Name", ValueType.STRING));
		act.addParameter(new Parameter("OID", ValueType.STRING));
		node.createChild("addOID").setAction(act).build().setSerializable(false);
		act = new Action(Permission.READ, new RemoveHandler());
		node.createChild("remove").setAction(act).build().setSerializable(false);
		act = new Action(Permission.READ, new AddFolderHandler());
		act.addParameter(new Parameter("Name", ValueType.STRING));
		node.createChild("addFolder").setAction(act).build().setSerializable(false);
		act = new Action(Permission.READ, new WalkHandler());
		act.addParameter(new Parameter("Name", ValueType.STRING));
		act.addParameter(new Parameter("OID", ValueType.STRING, new Value("0.0")));
		node.createChild("walk").setAction(act).build().setSerializable(false);

		if (!(this instanceof AgentNode)) {
			act = new Action(Permission.READ, new RenameHandler());
			act.addParameter(new Parameter("Name", ValueType.STRING, new Value(node.getName())));
			node.createChild("rename").setAction(act).build().setSerializable(false);
		}

		act = new Action(Permission.READ, new CopyHandler());
		act.addParameter(new Parameter("Name", ValueType.STRING));
		node.createChild("make copy").setAction(act).build().setSerializable(false);
	}

	SnmpNode(SnmpLink slink, Node mynode, AgentNode anode) {
		this(slink, mynode);
		this.root = anode;
	}

	static {
		LOGGER = LoggerFactory.getLogger(SnmpNode.class);
	}

	class WalkHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			final String name = event.getParameter("Name", ValueType.STRING).getString();
			String oid = event.getParameter("OID", ValueType.STRING).getString();
			if (oid.charAt(0) == '.')
				oid = oid.substring(1);
			Node response = node.createChild(name).build();
			Action act = new Action(Permission.READ, new Handler<ActionResult>() {
				public void handle(ActionResult event) {
					node.removeChild(name);
				}
			});
			response.createChild("remove").setAction(act).build().setSerializable(false);
			response.setAttribute("restoreType", new Value("walk"));
			link.mibUse.add(true);
			if (!link.mibnode.getAttribute("keep MIBs loaded").getBool())
				try {
					Thread.sleep(500);
				} catch (InterruptedException e) {
					LOGGER.debug("", e);
				}
			walk(response, new OID(oid));
		}
	}

	private void walk(final Node response, final OID oid) {
		PDU pdu = new PDU();
		pdu.add(new VariableBinding(oid));
		pdu.setType(PDU.GETNEXT);
		ResponseListener listener = new ResponseListener() {
			public void onResponse(ResponseEvent event) {
				LOGGER.trace("Received response PDU is: " + event.getResponse());
				LOGGER.trace("Received response PDU Error is: " + event.getError());
				LOGGER.trace("Received response PDU Peer Address is: " + event.getPeerAddress());
				((Snmp) event.getSource()).cancel(event.getRequest(), this);
				// LOGGER.debug("(Walking) Received response PDU is:
				// "+event.getResponse());
				if (event.getResponse() != null && !event.getResponse().get(0).isException()) {
					OID noid = event.getResponse().get(0).getOid();
					String val = event.getResponse().getVariable(noid).toString();
					String noidname = link.parseOid(noid);
					NodeBuilder builder = response.createChild(noidname);
					builder.setValueType(ValueType.STRING);
					builder.setValue(new Value(val));
					Node vnode = builder.build();
					vnode.setAttribute("oid", new Value(noid.toString()));
					vnode.setAttribute("syntax", new Value(event.getResponse().getVariable(noid).getSyntax()));
					createOidActions(vnode);
					link.setupOID(vnode, root);
					walk(response, noid);
				} else {
					link.mibUse.remove();
				}
			}
		};

		try {
			LOGGER.trace("sending getnext");
			LOGGER.trace("sending pdu: " + pdu + "   to target: " + root.target);
			if (root.target != null)
				snmp.send(pdu, root.target, null, listener);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			// e.printStackTrace();
			LOGGER.error("error during walk");
			LOGGER.debug("error:", e);
			link.mibUse.remove();
		}
	}

	class AddFolderHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			String name = event.getParameter("Name", ValueType.STRING).getString();
			new SnmpNode(link, node.createChild(name).build(), root);
		}
	}

	class RemoveHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			remove();
		}
	}

	void remove() {
		node.clearChildren();
		node.getParent().removeChild(node);
	}

	protected class CopyHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			String newname = event.getParameter("Name", ValueType.STRING).getString();
			if (newname.length() > 0 && !newname.equals(node.getName()))
				duplicate(newname);
		}
	}

	protected class RenameHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			String newname = event.getParameter("Name", ValueType.STRING).getString();
			if (newname.length() > 0 && !newname.equals(node.getName()))
				rename(newname);
		}
	}

	protected void rename(String newname) {
		duplicate(newname);
		remove();
	}

	protected void duplicate(String name) {
		JsonObject jobj = link.copySerializer.serialize();
		JsonObject parentobj = getParentJson(jobj);
		JsonObject nodeobj = parentobj.get(node.getName());
		parentobj.put(name, nodeobj);
		link.copyDeserializer.deserialize(jobj);
		Node newnode = node.getParent().getChild(name);
		SnmpNode sf = new SnmpNode(link, newnode, root);
		sf.restoreLastSession();
	}

	protected JsonObject getParentJson(JsonObject jobj) {
		return getParentJson(jobj, node);
	}

	private JsonObject getParentJson(JsonObject jobj, Node n) {
		if (n == root.node)
			return jobj;
		else
			return getParentJson(jobj, n.getParent()).get(n.getParent().getName());
	}

	class GetHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			final String name = event.getParameter("Name", ValueType.STRING).getString();
			String oid = event.getParameter("OID", ValueType.STRING).getString();
			addOid(name, oid, node);
		}
	}

	private void addOid(String name, String oid, Node fnode) {
		if (oid.charAt(0) == '.')
			oid = oid.substring(1);
		NodeBuilder builder = fnode.createChild(name);
		builder.setValueType(ValueType.STRING);
		Node response = builder.build();
		response.setAttribute("oid", new Value(oid));
		createOidActions(response);
		link.setupOID(response, root);
	}

	void sendGetRequest(final Node response) {
		if (root.target == null)
			return;
		PDU pdu;
		if (root.getVersion() == SnmpVersion.v3) {
			ScopedPDU spdu = new ScopedPDU();
			OctetString contextEngineId = AgentNode
					.createOctetString(root.node.getAttribute("Context Engine").getString());
			OctetString contextName = AgentNode.createOctetString(root.node.getAttribute("Context Name").getString());
			if (contextEngineId.length() > 0) {
				spdu.setContextEngineID(contextEngineId);
			}
			if (contextName.length() > 0) {
				spdu.setContextName(contextName);
			}
			pdu = spdu;
		} else {
			pdu = new PDU();
		}
		final String oid = response.getAttribute("oid").getString();
		pdu.add(new VariableBinding(new OID(oid)));
		pdu.setType(PDU.GET);
		ResponseListener listener = new ResponseListener() {
			public void onResponse(ResponseEvent event) {
				LOGGER.debug("Received response PDU is: " + event.getResponse());
				LOGGER.debug("Received response PDU Error is: " + event.getError());
				LOGGER.debug("Received response PDU Peer Address is: " + event.getPeerAddress());
				((Snmp) event.getSource()).cancel(event.getRequest(), this);
				// LOGGER.debug("Received response PDU is:
				// "+event.getResponse());
				Value val = null;
				ValueType vt = response.getValueType();
				if (event.getResponse() != null) {
					Variable var = event.getResponse().getVariable(new OID(oid));
					int syntax = var.getSyntax();
					switch (syntax) {
					case (SMIConstants.SYNTAX_COUNTER32):
					case (SMIConstants.SYNTAX_COUNTER64):
					case (SMIConstants.SYNTAX_GAUGE32):
					case (SMIConstants.SYNTAX_INTEGER):
						vt = ValueType.NUMBER;
						val = new Value(var.toLong());
						break;
					default:
						vt = ValueType.STRING;
						val = new Value(var.toString());
					}
					response.setAttribute("syntax", new Value(syntax));
				}
				if (vt != null && !vt.equals(response.getValueType())) {
					response.setValueType(vt);
				}
				response.setValue(val);
			}
		};
		try {
			LOGGER.debug("sending pdu: " + pdu + "   to target: " + root.target);
			if (root.target != null)
				snmp.send(pdu, root.target, null, listener);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			// e.printStackTrace();
			LOGGER.error("error:", e);
		}
	}

	void createOidActions(Node valnode) {
		Action act = new Action(Permission.READ, new RemoveOidHandler(valnode));
		valnode.createChild("remove").setAction(act).build().setSerializable(false);

        act = new Action(Permission.READ, new SetHandler(valnode));
		act.addParameter(new Parameter("value", ValueType.STRING));
        valnode.createChild("set").setAction(act).build().setSerializable(false);

		act = new Action(Permission.READ, new EditOidHandler(valnode));
		act.addParameter(new Parameter("Name", ValueType.STRING, new Value(valnode.getName())));
		act.addParameter(new Parameter("OID", ValueType.STRING, valnode.getAttribute("oid")));
		valnode.createChild("edit").setAction(act).build().setSerializable(false);

	}

	class SetHandler implements Handler<ValuePair> {
		private Node vnode;

		SetHandler(Node valnode) {
			vnode = valnode;
		}

		public void handle(ValuePair event) {
			if (!event.isFromExternalSource())
				return;
			PDU pdu = new PDU();
            Value oid = vnode.getAttribute("oid");
            // Value syntax = vnode.getAttribute("syntax");
            if (oid == null)
                return;
            int syntaxInt = SMIConstants.SYNTAX_NULL;
            // int syntaxInt = SMIConstants.SYNTAX_NULL;
            // if (syntax == null)
            //     syntaxInt = SMIConstants.SYNTAX_INTEGER;
            // if (syntax != null)
			//     syntaxInt = syntax.getNumber().intValue();
			// if (syntaxInt == SMIConstants.SYNTAX_NULL)
            //     return;
            String valstring = event.getParameter("value", ValueType.STRING).getString();
			Variable val = AbstractVariable.createFromSyntax(syntaxInt);
			if (!(val instanceof AssignableFromString))
				return;
			((AssignableFromString) val).setValue(valstring);
			pdu.add(new VariableBinding(new OID(oid.getString()), val));

			// try {
			// pdu.add(new VariableBinding(new OID(oid), val));
			// } catch (ParseException e) {
			// // TODO Auto-generated catch block
			// LOGGER.error("Error parsing value string");
			// e.printStackTrace();
			// LOGGER.debug("error:", e);
			// return;
			// }
			pdu.setType(PDU.SET);
			try {
				LOGGER.info("setting OID: " + oid.getString() + "   to value: " + valstring + "   on target: " + root.target);
				if (root.target != null)
					snmp.send(pdu, root.target, null, null);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				// e.printStackTrace();
				LOGGER.debug("error:", e);
			}

		}
	}

	class EditOidHandler implements Handler<ActionResult> {
		Node vnode;

		EditOidHandler(Node valnode) {
			vnode = valnode;
		}

		public void handle(ActionResult event) {
			String name = event.getParameter("Name", ValueType.STRING).getString();
			String oid = event.getParameter("OID", ValueType.STRING).getString();
			Node pnode = vnode.getParent();
			removeOid(vnode);
			addOid(name, oid, pnode);
		}
	}

	class RemoveOidHandler implements Handler<ActionResult> {
		Node toRemove;

		RemoveOidHandler(Node valnode) {
			toRemove = valnode;
		}

		public void handle(ActionResult event) {
			removeOid(toRemove);
		}

	}

	private void removeOid(Node toRemove) {
		toRemove.clearChildren();
		toRemove.getParent().removeChild(toRemove);
	}

	void restoreLastSession() {
		if (node.getChildren() == null)
			return;
		for (Node child : node.getChildren().values()) {
			Value restoreType = child.getAttribute("restoreType");
			if (restoreType != null && restoreType.getString().equals("folder")) {
				SnmpNode sn = new SnmpNode(link, child, root);
				sn.restoreLastSession();
			} else if (restoreType != null && restoreType.getString().equals("walk")) {
				restoreWalk(child);
			} else if (child.getValue() != null) {
				if (root == this && (child.getName().equals("TRAPS") || child.getName().equals("STATUS"))) {

				} else {
					createOidActions(child);
					link.setupOID(child, root);
				}
			} else if (child.getAction() == null) {
				node.removeChild(child);
			}
		}
	}

	private void restoreWalk(final Node wnode) {
		if (wnode.getChildren() != null) {
			for (Node subchild : wnode.getChildren().values()) {
				if (subchild.getValue() != null) {
					createOidActions(subchild);
					link.setupOID(subchild, root);
				}
			}
		}
		Action act = new Action(Permission.READ, new Handler<ActionResult>() {
			public void handle(ActionResult event) {
				node.removeChild(wnode);
			}
		});
		wnode.createChild("remove").setAction(act).build().setSerializable(false);
		act = new Action(Permission.READ, new Handler<ActionResult>() {
			public void handle(ActionResult event) {
				String newname = event.getParameter("Name", ValueType.STRING).getString();
				if (newname.trim().length() > 1 && !newname.equals(wnode.getName())) {
					copywalk(wnode, newname);
					node.removeChild(wnode);
				}
			}
		});
		act.addParameter(new Parameter("Name", ValueType.STRING));
		wnode.createChild("rename").setAction(act).build().setSerializable(false);
		act = new Action(Permission.READ, new Handler<ActionResult>() {
			public void handle(ActionResult event) {
				String newname = event.getParameter("Name", ValueType.STRING).getString();
				if (newname.trim().length() > 1 && !newname.equals(wnode.getName())) {
					copywalk(wnode, newname);
				}
			}
		});
		act.addParameter(new Parameter("Name", ValueType.STRING));
		wnode.createChild("make copy").setAction(act).build().setSerializable(false);
	}

	protected void copywalk(Node wnode, String name) {
		JsonObject jobj = link.copySerializer.serialize();
		JsonObject parentobj = getParentJson(jobj).get(node.getName());
		JsonObject walkobj = parentobj.get(wnode.getName());
		parentobj.put(name, walkobj);
		link.copyDeserializer.deserialize(jobj);
		Node newnode = node.getChild(name);
		restoreWalk(newnode);
	}

}
