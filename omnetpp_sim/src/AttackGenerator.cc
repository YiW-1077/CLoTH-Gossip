#include "AttackGenerator.h"

Define_Module(AttackGenerator);

void AttackGenerator::initialize() {
    attackIntensity = par("attackIntensity");
    attackStartTime = par("attackStartTime");
    attackDuration = par("attackDuration");
    totalAttacks = 0;

    EV << "AttackGenerator initialized" << endl;
    EV << "  Attack start: " << attackStartTime << "s" << endl;
    EV << "  Attack duration: " << attackDuration << "s" << endl;
    EV << "  Attack intensity: " << attackIntensity << endl;
}

void AttackGenerator::handleMessage(cMessage *msg) {
    delete msg;
}

void AttackGenerator::finish() {
    EV << "AttackGenerator finished - Total attacks: " << totalAttacks << endl;
}
