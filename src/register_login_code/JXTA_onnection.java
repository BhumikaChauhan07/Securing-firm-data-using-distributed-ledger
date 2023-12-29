package register_login_code;
import net.jxta.exception.PeerGroupException;
import net.jxta.id.ID;
import net.jxta.id.IDFactory;
import net.jxta.peergroup.PeerGroup;
import net.jxta.peergroup.PeerGroupFactory;
import net.jxta.platform.NetworkConfigurator;
import net.jxta.platform.NetworkManager;

import java.io.File;
import java.io.IOException;
import java.util.Enumeration;

public class JXTA_onnection {


	

	    private static final String NETWORK_NAME = "MyJxtaNetwork";
	    private static final String NODE_NAME_PREFIX = "Node";

	    public static void main(String[] args) {
	        try {
	            // Create and start the network manager
	            NetworkManager manager = new NetworkManager(NetworkManager.ConfigMode.EDGE, NETWORK_NAME);
	            NetworkConfigurator configurator = manager.getConfigurator();

	            // Set the name of the node
	            configurator.setName(NODE_NAME_PREFIX + manager.getNetPeerGroup().getPeerID().toString());

	            // Start JXTA
	            PeerGroup netPeerGroup = manager.startNetwork();

	            // Get the list of all nodes in the peer group
	            Enumeration<ID> peerIDs = netPeerGroup.getPeerIDs();

	            // Print information about each node
	            while (peerIDs.hasMoreElements()) {
	                ID peerID = peerIDs.nextElement();
	                System.out.println("Node: " + peerID);
	            }

	            // Stop the network manager when done
	            manager.stopNetwork();

	        } catch (IOException | PeerGroupException e) {
	            e.printStackTrace();
	        }
	    }
	}

}
