#################################
## Configuration file for DAST ##
#################################

# Configuration File for OWASP ZAProxy
class TestConfig():
    apiKey='test'
    localProxy = {"http":"http://127.0.0.1:8090/", "https":"http://127.0.0.1:8090/"}
    scanPolicyName= 'Default Policy'
    useContextForScan = True
    defineNewContext = True
    isNewSession = True
    sessionManagement = 'cookieBasedSessionManagement'
    authMethod = 'formBasedAuthentication'
    createUser = True
    isLoggedInIndicator = False
    useScanPolicy = False
    useAjaxSpider = True
    shutdownOnceFinished = False
    contextId = 7
    target = 'http://127.0.0.1:4000/login' 
    sessionName = 'Test2'
#    globalExcludeUrl = ['^(?:(?!http:\/\/localhost).*).$']
    contextName = 'Test2'
    contextIncludeURL = ['http://127.0.0.1:4000/login.*','http://127.0.0.1:4000/contributions','http://127.0.0.1:4000/','http://127.0.0.1:4000/dashboard',
                         'http://127.0.0.1:4000/allocations/4','http://127.0.0.1:4000/memos','http://127.0.0.1:4000/profile','http://127.0.0.1:4000/research']

    contextExcludeURL = []

    authParams = "".join('loginUrl=http://127.0.0.1:4000/login' 
                    'userName%3Dtestuser%26password%3Dtestuser%26_csrf%3D')             

    indicatorRegex = '\Q<a href="/signup">New user? Sign Up</a>\E'
    userList = [
        {'name': 'testuser', 'credentials': 'userName=jdoe&password=johnkdoe'}
    ]

    target = 'http://127.0.0.1:4000/login' 

    applicationURL = []
