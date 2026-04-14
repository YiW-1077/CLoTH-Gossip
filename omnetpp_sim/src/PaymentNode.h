#ifndef PAYMENTNODE_H_
#define PAYMENTNODE_H_

#include <omnetpp.h>
#include <vector>
#include <map>

using namespace omnetpp;

struct PaymentRecord {
    int paymentId;
    int senderId;
    int receiverId;
    double amount;
    double startTime;
    double endTime;
    double normalDelay;
    double actualDelay;
    double delayIncrease;
    bool underAttack;
    int attackIntensity;
    std::string attackType;
};

class PaymentNode : public cSimpleModule {
private:
    int nodeId;
    double processingTime;
    double attackStartTime;
    double attackDuration;
    double attackDelayFactor;
    bool isUnderAttack;
    std::vector<PaymentRecord> paymentLog;
    int nextPaymentId;

    void recordPayment(const PaymentRecord& record);
    double calculateAttackDelay(double baseDelay);
    void writeOutputFile();

protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;
};

#endif
