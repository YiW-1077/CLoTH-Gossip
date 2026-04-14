#include "PaymentNode.h"
#include <fstream>
#include <sstream>
#include <iomanip>

Define_Module(PaymentNode);

void PaymentNode::initialize() {
    nodeId = par("nodeId").intValue();
    processingTime = par("processingTime");
    attackStartTime = par("attackStartTime");
    attackDuration = par("attackDuration");
    attackDelayFactor = par("attackDelayFactor");
    isUnderAttack = false;
    nextPaymentId = 0;

    EV << "PaymentNode " << nodeId << " initialized" << endl;

    // Schedule attack start event
    if (attackDuration > 0) {
        cMessage *attackStart = new cMessage("attack_start");
        scheduleAt(attackStartTime, attackStart);
    }
}

void PaymentNode::handleMessage(cMessage *msg) {
    if (strcmp(msg->getName(), "attack_start") == 0) {
        isUnderAttack = true;
        EV << "Attack started on node " << nodeId << " at time " << simTime() << endl;

        cMessage *attackEnd = new cMessage("attack_end");
        scheduleAt(simTime() + attackDuration, attackEnd);
        delete msg;
    }
    else if (strcmp(msg->getName(), "attack_end") == 0) {
        isUnderAttack = false;
        EV << "Attack ended on node " << nodeId << " at time " << simTime() << endl;
        delete msg;
    }
    else if (strcmp(msg->getName(), "payment") == 0) {
        double baseDelay = processingTime;
        double actualDelay = baseDelay;
        int attackIntensity = 0;
        std::string attackType = "none";

        if (isUnderAttack) {
            actualDelay = calculateAttackDelay(baseDelay);
            attackIntensity = (int)(attackDelayFactor * 100);
            attackType = "ddos";
        }

        PaymentRecord record;
        record.paymentId = nextPaymentId++;
        record.senderId = nodeId;
        record.receiverId = (nodeId + 1) % (int)getParentModule()->par("numNodes");
        record.amount = 1000.0;  // Default amount in msat
        record.startTime = simTime().dbl();
        record.endTime = simTime().dbl() + actualDelay;
        record.normalDelay = baseDelay;
        record.actualDelay = actualDelay;
        record.delayIncrease = actualDelay - baseDelay;
        record.underAttack = isUnderAttack;
        record.attackIntensity = attackIntensity;
        record.attackType = attackType;

        recordPayment(record);

        EV << "Payment " << record.paymentId << " processed on node " << nodeId
           << " - Delay: " << actualDelay << "ms (Base: " << baseDelay << "ms)"
           << (isUnderAttack ? " [UNDER ATTACK]" : "") << endl;

        delete msg;
    }
}

double PaymentNode::calculateAttackDelay(double baseDelay) {
    // Attack increases delay exponentially based on attack intensity
    // delayFactor ranges from 1.0 (no attack) to higher values
    double additionalDelay = baseDelay * (attackDelayFactor - 1.0) * 10;
    return baseDelay + additionalDelay;
}

void PaymentNode::recordPayment(const PaymentRecord& record) {
    paymentLog.push_back(record);
}

void PaymentNode::finish() {
    writeOutputFile();
    EV << "PaymentNode " << nodeId << " finished with " << paymentLog.size() << " payments" << endl;
}

void PaymentNode::writeOutputFile() {
    std::ostringstream filename;
    filename << "result/attack_delays_node_" << nodeId << ".csv";

    std::ofstream file(filename.str());
    if (!file.is_open()) {
        EV << "Warning: Cannot open file " << filename.str() << endl;
        return;
    }

    // Write header
    file << "payment_id,sender_id,receiver_id,amount,start_time,end_time,"
         << "normal_delay,actual_delay,delay_increase,under_attack,"
         << "attack_intensity,attack_type\n";

    // Write payment records
    for (const auto& record : paymentLog) {
        file << record.paymentId << ","
             << record.senderId << ","
             << record.receiverId << ","
             << std::fixed << std::setprecision(2) << record.amount << ","
             << std::fixed << std::setprecision(6) << record.startTime << ","
             << std::fixed << std::setprecision(6) << record.endTime << ","
             << std::fixed << std::setprecision(6) << record.normalDelay << ","
             << std::fixed << std::setprecision(6) << record.actualDelay << ","
             << std::fixed << std::setprecision(6) << record.delayIncrease << ","
             << (record.underAttack ? "1" : "0") << ","
             << record.attackIntensity << ","
             << record.attackType << "\n";
    }

    file.close();
}
