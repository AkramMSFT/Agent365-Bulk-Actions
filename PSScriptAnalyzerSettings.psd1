@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        'PSAvoidUsingWriteHost'            # interactive console tool; colour output is intentional
        'PSUseSingularNouns'               # internal helper names
        'PSReviewUnusedParameter'          # parameters are read by helper functions through script scope
        'PSUseShouldProcessForStateChangingFunctions'
        'PSAvoidGlobalVars'
    )
}
