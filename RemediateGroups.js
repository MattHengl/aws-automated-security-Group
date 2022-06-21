/*!
     * Copyright 2017-2017 Mutual of Enumclaw. All Rights Reserved.
     * License: Public
*/

//Mutual of Enumclaw 
//
//Matthew Hengl and Jocelyn Borovich - 2019 :) :)
//Lane Hale Jest tested June 2020 :)
//
//Main file that controls remediation and notifications of all IAM Group events.
//Remediates actions when possible or necessary based on launch type and tagging. Then, notifies the user/security. 

//Make sure to that the master.invalid call does NOT have a ! infront of it
//Make sure to delete or comment out the change in the process.env.environtment

const AWS = require('aws-sdk');
AWS.config.update({ region: process.env.region });
let iam = new AWS.IAM();
const label = require('epsagon');
const Master = require("aws-automated-master-class/MasterClass").handler;
let path = require("aws-automated-master-class/MasterClass").path;
let master = new Master();
let callRemediate = remediate;

//Only used for testing purposes
setIamFunction = (value, funct) => {
    iam[value] = funct;
};

const actions = {
    CreateGroup: { action: 'CreateGroup', apiFunction: 'createGroup', remediateAction: 'DeleteGroup' },
    DeleteGroup: { action: 'DeleteGroup', apiFunction: 'deleteGroup', remediateAction: 'CreateGroup' },
    PutGroupPolicy: { action: 'PutGroupPolicy', apiFunction: 'putGroupPolicy', remediateAction: 'DeleteGroupPolicy' },
    DeleteGroupPolicy: { action: 'DeleteGroupPolicy', apiFunction: 'deleteGroupPolicy', remediateAction: 'PutGroupPolicy' },
    AttachGroupPolicy: { action: 'AttachGroupPolicy', apiFunction: 'attachGroupPolicy', remediateAction: 'DetachGroupPolicy' },
    DetachGroupPolicy: { action: 'DetachGroupPolicy', apiFunction: 'detachGroupPolicy', remediateAction: 'AttachGroupPolicy' },
};

//remediates a specific action after receiving an event log
async function handleEvent(event) {
    console.log(JSON.stringify(event));
    path.p = 'Path: \nEntering handleEvent';

    try {
        event = master.devTest(event);
        //Checks the event log for any previous errors. Stops the function if there is an error.
        if (master.errorInLog(event)) {
            //      path.n += 'Error in Log';
            console.log(path.p);
            return;
        }

        //Checks if the log came from this function, quits the program if it does.
        if (await master.selfInvoked(event)) {
            return;
        }

        console.log(`"${event.detail.requestParameters.groupName}" is being inspected----------`);
        console.log(`Event action is ${event.detail.eventName}---------- `);

        //Checks to see who is doing the action, if it's one of the two interns. RUN IT!
        //if(master.checkKeyUser(event, "groupName")){
        //checks if the log is invalid
        if (master.invalid(event)) {
            await master.notifyUser(event, await callRemediate(event), 'S3');
        }
        //await master.notifyUser(event, await callRemediate(event), 'S3');
    } catch (e) {
        console.log(e);
        path.p += '\nERROR';
        console.log(path.p);
        return e;
    }
    console.log(path.p);
}

async function remediate(event) {

    console.log('Entered into the remediation function')
    path.p += '\nEntered the remediation function';

    //Sets up required parameters
    const erp = event.detail.requestParameters;
    let params = {
        GroupName: erp.groupName
    };

    console.log('Calling getResults in master');
    let results = master.getResults(event, params);

    path.p += `\nAction: ${results.Action}`;
    console.log(`Action: ${results.Action}`);

    try {
        let action = actions[results.Action];
        // path.p +=`\nAction: ${JSON.stringify(action)}`;

        if (action) {
            let remediateAction = actions[action.remediateAction];
            // path.p +=`\nRemediate Action: ${JSON.stringify(remediateAction)}`;

            //Decides, based on the incoming event, which function to call to perform remediation
            switch (action) {
                case actions.AttachGroupPolicy:
                case actions.DetachGroupPolicy:
                    params.PolicyArn = erp.policyArn;
                    //Override Remediation Control. Only used for testing purposes
                    await overrideFunction(remediateAction.apiFunction, params);
                    results.PolicyArn = erp.policyArn;
                    results.Response = remediateAction.action;
                    break;
                case actions.PutGroupPolicy:
                    params.PolicyName = erp.policyName;
                    //Override Remediation Control. Only used for testing purposes
                    await overrideFunction(remediateAction.apiFunction, params);
                    results.PolicyName = erp.policyName;
                    results.Response = remediateAction.action;
                    break;
                case actions.CreateGroup:
                    //Override Remediation Control. Only used for testing purposes
                    await overrideFunction(remediateAction.apiFunction, params);
                    results.Response = remediateAction.action;
                    break;
                case actions.DeleteGroupPolicy:
                case actions.DeleteGroup:
                    results.PolicyName = erp.policyName;
                    results.Response = "Remediation could not be performed";
                    break;
            };
        }
        else {
            path.p += '\nUnexpected Action found';
            console.log(`Unexpected Action found: ${results.Action}`);
        }
    } catch (e) {
        console.log('Catch ' + e.code);
        console.log('Catch ' + e);
        //            if (e.code == 'NoSuchEntity') {
        console.log(e);
        path.p += '\nNoSuchEntity error caught';
        console.log("**************NoSuchEntity error caught**************");
        return e;
        //            }
    }
    console.log("Remediation completed-----------------");
    results.Reason = 'Improper Launch';
    if (results.Response == 'Remediation could not be performed') {
        delete results.Reason;
    }
    path.p += '\nRemediation was finished, notifying user now';
    return results;
}

async function overrideFunction(apiFunction, params) {
    // Uses the "run" environment bool to determine if override is necessary
    if (process.env.run == 'false') {
        await setIamFunction(apiFunction, (params) => {
            console.log(`Overriding ${apiFunction}`);
            return { promise: () => { } };
        });
    }
    await iam[apiFunction](params).promise();
};

exports.handler = handleEvent;
exports.remediate = remediate;

//overrides the given function (only for jest testing)
exports.setIamFunction = (value, funct) => {
    iam[value] = funct;
};
exports.setRemediate = (funct) => {
    callRemediate = funct;
};