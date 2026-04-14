package simulations;

simple PaymentNode
{
    parameters:
        int nodeId;
        double processingTime @unit(ms) = default(10ms);
        double attackStartTime @unit(s) = default(0s);
        double attackDuration @unit(s) = default(0s);
        double attackDelayFactor = default(1.0);
        @display("i=block/routing");
    gates:
        inout link[];
}

simple AttackGenerator
{
    parameters:
        double attackIntensity = default(0.5);
        double attackStartTime @unit(s) = default(10s);
        double attackDuration @unit(s) = default(30s);
        @display("i=block/source");
}

network PaymentNetwork
{
    parameters:
        int numNodes = default(10);
        double linkDelay @unit(ms) = default(10ms);
        double attackStartTime @unit(s) = default(20s);
        double attackDuration @unit(s) = default(30s);
        double attackIntensity = default(0.5);
        
    submodules:
        node[numNodes]: PaymentNode {
            parameters:
                nodeId = index;
                attackStartTime = parent.attackStartTime;
                attackDuration = parent.attackDuration;
                attackDelayFactor = parent.attackIntensity;
        }
        attackGen: AttackGenerator {
            parameters:
                attackIntensity = parent.attackIntensity;
                attackStartTime = parent.attackStartTime;
                attackDuration = parent.attackDuration;
        }
    
    connections allowunconnected:
        // Mesh network topology
        for i=0..numNodes-1, for j=i+1..numNodes-1 {
            node[i].link++ <--> {delay: parent.linkDelay;} <--> node[j].link++;
        }
}
