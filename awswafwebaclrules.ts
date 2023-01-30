import { CfnWebACL } from 'aws-cdk-lib/aws-wafv2';

interface WafRule {
  name: string;
  rule: CfnWebACL.RuleProperty;
}

export const rateBasedRules: WafRule[] = [
  {
    name: 'MyEv-RateBasedRulesPublicRoutes',
    rule: {
      name: 'MyEv-RateBasedRulesPublicRoutes',
      priority: 100,
      action: {
        block: {}
      },
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: 'RateBasedRulesPublicRoutes'
      },
      statement: {
        rateBasedStatement: {
          limit: 100,
          aggregateKeyType: 'IP',
          scopeDownStatement: {
            regexMatchStatement: {
              fieldToMatch: {
                uriPath: {}
              },
              textTransformations: [
                {
                  type: 'NONE',
                  priority: 0
                }
              ],
              regexString: [
                '^/login',
                '^/forgot',
                '^/reset',
                '^/signup',
                '^/account/password',
                '^/auth/facebook',
                '^/auth/google',
                '^/related',
                '^/dogs-like-mine',
                '^/dog(s?)/*/',
                '^/ogimage',
                '^/redirect-to-checkout',
                '^/members/reports'
            ].join('|')
            }
          }
        }
      }
    }
  },
  {
    name: 'MyEv-RateBasedRulesSAPIRoutes',
    rule: {
      name: 'MyEv-RateBasedRulesSAPIRoutes',
      priority: 200,
      statement: {
        rateBasedStatement: {
          limit: 2000,
          aggregateKeyType: 'IP',
          scopeDownStatement: {
            byteMatchStatement: {
              searchString: '/sapi',
              fieldToMatch: {
                uriPath: {}
              },
              textTransformations: [
                {
                  priority: 0,
                  type: 'NONE'
                }
              ],
              positionalConstraint: 'STARTS_WITH'
            }
          }
        }
      },
      action: {
        block: {}
      },
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: 'RateBasedRulesSAPIRoutes'
      }
    },
  },
  {
    name: 'MyEv-RateBasedRulesPublicAPIRoutes',
    rule: {
      name: 'MyEv-RateBasedRulesPublicAPIRoutes',
      priority: 300,
      action: {
        block: {}
      },
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: 'RateBasedRulesPublicAPIRoutes'
      },
      statement: {
        rateBasedStatement: {
          limit: 200,
          aggregateKeyType: 'IP',
          scopeDownStatement: {
            andStatement: {
              statements: [
                {
                  byteMatchStatement: {
                    fieldToMatch: {
                      uriPath: {}
                    },
                    positionalConstraint: 'STARTS_WITH',
                    searchString: '/api',
                    textTransformations: [
                      {
                        type: 'NONE',
                        priority: 0
                      }
                    ]
                  }
                },
                {
                  notStatement: {
                    statement: {
                      byteMatchStatement: {
                        fieldToMatch: {
                          uriPath: {}
                        },
                        positionalConstraint: 'STARTS_WITH',
                        searchString: '/api/qualtrics',
                        textTransformations: [
                          {
                            type: 'NONE',
                            priority: 0
                          }
                        ]
                      }
                    }
                  }
                }
              ]
            }
          }
        }
      }
    }
  },
  {
    name: 'MyEv-RateBasedRulesQualtricsApi',
    rule: {
      name: 'MyEv-RateBasedRulesQualtricsApi',
      priority: 400,
      action: {
        block: {}
      },
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: 'RateBasedRulesQualtricsApi'
      },
      statement: {
        rateBasedStatement: {
          limit: 3000,
          aggregateKeyType: 'IP',
          scopeDownStatement: {
            byteMatchStatement: {
              fieldToMatch: {
                uriPath: {}
              },
              positionalConstraint: 'STARTS_WITH',
              searchString: '/api/qualtrics',
              textTransformations: [
                {
                  type: 'NONE',
                  priority: 0
                }
              ]
            }
          }
        }
      }
    }
  }
]

export const awsManagedRules: WafRule[] = [
  // AWS IP Reputation list includes known malicious actors/bots and is regularly updated
  {
    name: 'AWS-AWSManagedRulesAmazonIpReputationList',
    rule: {
      name: 'AWS-AWSManagedRulesAmazonIpReputationList',
      priority: 1,
      statement: {
        managedRuleGroupStatement: {
          vendorName: 'AWS',
          name: 'AWSManagedRulesAmazonIpReputationList',
        },
      },
      overrideAction: {
        none: {},
      },
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: 'AWSManagedRulesAmazonIpReputationList',
      },
    },
  },
  // Common Rule Set aligns with major portions of OWASP Core Rule Set
  {
    name: 'AWS-AWSManagedRulesCommonRuleSet',
    rule: {
      name: 'AWS-AWSManagedRulesCommonRuleSet',
      priority: 2,
      statement: {
        managedRuleGroupStatement: {
          vendorName: 'AWS',
          name: 'AWSManagedRulesCommonRuleSet',
          // Excluding body size rules
          // Excluded rules get COUNTED but not BLOCKED
          excludedRules: [
            { name: 'GenericRFI_BODY' },
            { name: 'SizeRestrictions_BODY' },
            { name: 'CrossSiteScripting_COOKIE' },
          ],
        },
      },
      overrideAction: {
        none: {},
      },
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: 'AWS-AWSManagedRulesCommonRuleSet',
      },
    },
  },
  // Blocks invalid/exploit request patterns.
  {
    name: 'AWSManagedRulesKnownBadInputsRuleSet',
    rule: {
      name: 'AWSManagedRulesKnownBadInputsRuleSet',
      priority: 3,
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: 'AWSManagedRulesKnownBadInputsRuleSet',
      },
      overrideAction: {
        none: {},
      },
      statement: {
        managedRuleGroupStatement: {
          vendorName: 'AWS',
          name: 'AWSManagedRulesKnownBadInputsRuleSet',
          excludedRules: [],
        },
      },
    },
  },
  // Blocks common SQL Injection
  {
    name: 'AWSManagedRulesSQLiRuleSet',
    rule: {
      name: 'AWSManagedRulesSQLiRuleSet',
      priority: 4,
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: 'AWSManagedRulesSQLiRuleSet',
      },
      overrideAction: {
        none: {},
      },
      statement: {
        managedRuleGroupStatement: {
          vendorName: 'AWS',
          name: 'AWSManagedRulesSQLiRuleSet',
          excludedRules: [],
        },
      },
    },
  },
  // Blocks attacks targeting LFI for linux systems
  {
    name: 'AWSManagedRuleLinux',
    rule: {
      name: 'AWSManagedRuleLinux',
      priority: 5,
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: 'AWSManagedRuleLinux',
      },
      overrideAction: {
        none: {},
      },
      statement: {
        managedRuleGroupStatement: {
          vendorName: 'AWS',
          name: 'AWSManagedRulesLinuxRuleSet',
          excludedRules: [],
        },
      },
    },
  },
];