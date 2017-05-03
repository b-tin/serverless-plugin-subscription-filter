'use strict';

const _ = require('lodash');
const AWS = require('aws-sdk');

class ServerlessPluginSubscriptionFilter {
  constructor(serverless, options) {
    this.serverless = serverless;
    this.options = options;

    this.provider = this.serverless.getProvider('aws');
    AWS.config.update({
      region: this.serverless.service.provider.region
    });

    this.hooks = {
      'deploy:compileEvents': this.compileSubscriptionFilterEvents.bind(this),
    };
  }

  compileSubscriptionFilterEvents() {
    const stage = this.provider.getStage();
    const functions = this.serverless.service.getAllFunctions();
    const promises = [];

    functions.forEach((functionName) => {
      const functionObj = this.serverless.service.getFunction(functionName);

      functionObj.events.forEach((event) => {
        const subscriptionFilter = event.subscriptionFilter;

        if (this.validateSettings(subscriptionFilter)) {
          if (subscriptionFilter.stage != stage) {
            // Skip compile
            this.serverless.cli.log(`Skipping to compile ${subscriptionFilter.logGroupName} subscription filter object...`);
            return;
          }

          promises.push(this.doCompile(subscriptionFilter, functionName));
        }
      });
    });

    return Promise.all(promises);
  }

  validateSettings(setting) {
    if (!setting) {
      // Skip compile
      return false;
    }

    if (!setting.stage || typeof setting.stage != 'string') {
      const errorMessage = [
        'You can\'t set stage properties of a subscriptionFilter event.',
        'stage propertiy is required.'
      ].join(' ');
      throw new this.serverless.classes.Error(errorMessage);
    }

    if (!setting.logGroupName || typeof setting.logGroupName != 'string') {
      const errorMessage = [
        'You can\'t set logGroupName properties of a subscriptionFilter event.',
        'logGroupName propertiy is required.'
      ].join(' ');
      throw new this.serverless.classes.Error(errorMessage);
    }

    if (!setting.filterPattern || typeof setting.filterPattern != 'string') {
      const errorMessage = [
        'You can\'t set filterPattern properties of a subscriptionFilter event.',
        'filterPattern propertiy is required.'
      ].join(' ');
      throw new this.serverless.classes.Error(errorMessage);
    }

    return true;
  }

  doCompile(setting, functionName) {
    this.serverless.cli.log(`Compiling ${setting.logGroupName} subscription filter object...`);

    return this.getLogGroupArn(setting.logGroupName)
      .then((logGroupArn) => {
        return this.compilePermission(setting, functionName, logGroupArn);
      })
      .then((newPermissionObject) => {
        _.merge(
          this.serverless.service.provider.compiledCloudFormationTemplate.Resources,
          newPermissionObject
        );

        return this.compileSubscriptionFilter(setting, functionName);
      })
      .then((newSubscriptionFilterObject) => {
        _.merge(
          this.serverless.service.provider.compiledCloudFormationTemplate.Resources,
          newSubscriptionFilterObject
        );
      })
      .catch((err) => {
        throw new this.serverless.classes.Error(err.message);
      });
  }

  compileSubscriptionFilter(setting, functionName) {
    return new Promise((resolve, _reject) => {
      const lambdaLogicalId = this.provider.naming.getLambdaLogicalId(functionName);
      const lambdaPermissionLogicalId = this.getLambdaPermissionLogicalId(functionName, setting.logGroupName);
      const filterPattern = this.escapeDoubleQuote(setting.filterPattern);
      const logGroupName = setting.logGroupName;
      const subscriptionFilterTemplate = `
        {
          "Type" : "AWS::Logs::SubscriptionFilter",
          "Properties" : {
            "DestinationArn" : { "Fn::GetAtt": ["${lambdaLogicalId}", "Arn"] },
            "FilterPattern" : "${filterPattern}",
            "LogGroupName" : "${logGroupName}"
          },
          "DependsOn": "${lambdaPermissionLogicalId}"
        }
      `;
      const subscriptionFilterLogicalId = this.getSubscriptionFilterLogicalId(functionName, setting.logGroupName);
      const newSubscriptionFilterObject = {
        [subscriptionFilterLogicalId]: JSON.parse(subscriptionFilterTemplate)
      };

      resolve(newSubscriptionFilterObject);
    });
  }

  compilePermission(setting, functionName, logGroupArn) {
    return new Promise((resolve, reject) => {
      const lambdaLogicalId = this.provider.naming.getLambdaLogicalId(functionName);
      const region = this.provider.getRegion();
      const permissionTemplate = `
        {
          "Type": "AWS::Lambda::Permission",
          "Properties": {
            "FunctionName": { "Fn::GetAtt": ["${lambdaLogicalId}", "Arn"] },
            "Action": "lambda:InvokeFunction",
            "Principal": "logs.${region}.amazonaws.com",
            "SourceArn": "${logGroupArn}"
          }
        }
      `;
      const lambdaPermissionLogicalId = this.getLambdaPermissionLogicalId(functionName, setting.logGroupName);
      const newPermissionObject = {
        [lambdaPermissionLogicalId]: JSON.parse(permissionTemplate)
      };

      resolve(newPermissionObject);
    });
  }

  getLogGroupArn(logGroupName, nextToken = null) {
    return new Promise((resolve, reject) => {
      const cloudWatchLogs = new AWS.CloudWatchLogs();
      const params = {
        logGroupNamePrefix: logGroupName,
        nextToken
      };

      cloudWatchLogs.describeLogGroups(params).promise()
        .then((data) => {
          const logGroups = data.logGroups;
          if (logGroups.length === 0) {
            reject(new Error('LogGroup not found'));
          }

          const logGroup = _.find(logGroups, { logGroupName: logGroupName });
          if (!logGroup) {
            return this.getLogGroupArn(logGroupName, data.nextToken);
          }

          resolve(logGroup.arn);
        })
        .catch((err) => {
          reject(err);
        });
    });
  }

  getSubscriptionFilterLogicalId(functionName, logGroupName) {
    const normalizedFunctionName = this.provider.naming.getNormalizedFunctionName(functionName);
    const normalizedLogGroupName = this.provider.naming.normalizeNameToAlphaNumericOnly(logGroupName);

    return `${normalizedFunctionName}SubscriptionFilter${normalizedLogGroupName}`;
  }

  getLambdaPermissionLogicalId(functionName, logGroupName) {
    const normalizedFunctionName = this.provider.naming.getNormalizedFunctionName(functionName);
    const normalizedLogGroupName = this.provider.naming.normalizeNameToAlphaNumericOnly(logGroupName);

    return `${normalizedFunctionName}LambdaPermission${normalizedLogGroupName}`;
  }

  escapeDoubleQuote(str) {
    return str.replace(/\"/g, '\\"');
  }
}

module.exports = ServerlessPluginSubscriptionFilter;
