#ifndef ATTACKGENERATOR_H_
#define ATTACKGENERATOR_H_

#include <omnetpp.h>

using namespace omnetpp;

class AttackGenerator : public cSimpleModule {
private:
    double attackIntensity;
    double attackStartTime;
    double attackDuration;
    int totalAttacks;

protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;
};

#endif
