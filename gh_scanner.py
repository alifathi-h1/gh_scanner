import time
import argparse
import sys
import re
import json
import os
import pyfiglet
from github import Github
from colorama import Fore


class GithubScanner:

    def __init__(self, targets, scan_memebers):

        self.targets = targets
        self.scan_memebers = scan_memebers
        self.ACCESS_TOKEN = os.environ.get('GITHUB_API_KEY')
        if self.ACCESS_TOKEN is None:
            print(Fore.RED)
            print(
                '\n [--] Please Configure GITHUB_API_KEY as Env Variable first. \n')
            sys.exit()

        self.g = ''
        self.key_hacks = {'Heroku API Key': 'api.heroku.com',
                          'Slack Webhook': 'https://hooks.slack.com/services',
                          'Slack API Token': 'https://slack.com/api',
                          'SendGrid API Token': 'https://api.sendgrid.com/v3',
                          'Square API Key': 'https://squareup.com/',
                          'Dropbox API Token': 'https://api.dropboxapi.com',
                          'Firebase': 'identitytoolkit.googleapis.com',
                          'Firebase Cloud Messaging': 'fcm.googleapis.com',
                          'Twilio Account_sid and Auth token': 'https://api.twilio.com/',
                          'Twitter API Secret': 'https://api.twitter.com/oauth2/token',
                          'Twitter Bearer token': 'https://api.twitter.com/',
                          'FreshDesk API Key': 'https://domain.freshdesk.com',
                          'HubSpot API key': 'https://api.hubapi.com/',
                          'JumpCloud API Key': 'https://console.jumpcloud.com',
                          'Microsoft Azure Tenant': 'https://login.microsoftonline.com',
                          'Mapbox API key': 'https://api.mapbox.com',
                          'Algolia API key': 'algolianet.com',
                          'Deviant Art Secret': 'https://www.deviantart.com/oauth2',
                          'Deviant Art Access Token': 'https://www.deviantart.com/api/',
                          'Salesforce API key': 'salesforce.com',
                          'BrowserStack Access Key': 'https://api.browserstack.com',
                          'Pagerduty API token': 'api.pagerduty.com',
                          'Zendesk Access token': 'zendesk.com',
                          'Bit.ly Access token': 'api-ssl.bitly.com',
                          'Asana Access token': 'app.asana.com',
                          'Branch.IO Key and Secret': 'api2.branch.io',
                          'WPEngine API Key': 'api.wpengine.com',
                          'DataDog API key': 'api.datadoghq.com',
                          'Travis CI API token': 'api.travis-ci.com',
                          'WakaTime API Key': 'wakatime.com',
                          'Spotify Access Token': 'api.spotify.com',
                          'Instagram Basic Display API Access Token': 'graph.instagram.com',
                          'Instagram Graph API Access Token': 'graph.facebook.com',
                          'Gitlab personal access token': 'https://gitlab',
                          'Stripe Live Token': 'api.stripe.com',
                          'Paypal client id and secret key': 'paypal.com',
                          'Razorpay API key and Secret key': 'api.razorpay.com',
                          'CircleCI Access Token': 'circle-token',
                          'Loqate API key': 'api.addressy.com',
                          'Ipstack API Key': 'api.ipstack.com',
                          'NPM token': 'registry.npmjs.org/:_authToken',
                          'SauceLabs Username and access Key': 'saucelabs.com',
                          'Facebook AppSecret': 'graph.facebook.com/oauth/access_token',
                          'Facebook Access Token': 'developers.facebook.com/tools/debug/accesstoken/?access_token=',
                          'Pendo Integration Key': 'app.pendo.io',
                          'Github client id and client secret': 'https://api.github.com/users/',
                          '.npmrc _auth': 'filename:.npmrc _auth',
                          'dockercfg': 'filename:.dockercfg auth',
                          'Pem Private': 'extension:pem private',
                          'PPK Private': 'extension:ppk private',
                          'id_dsa file': 'filename:id_rsa or filename:id_dsa',
                          'MySql': 'extension:sql mysql dump',
                          'Mysql Password': 'extension:sql mysql dump password',
                          'AWS Credential': 'filename:credentials aws_access_key_id',
                          's3cfg': 'filename:.s3cfg',
                          'WordPress Config file': 'filename:wp-config.php',
                          '.htpasswd': 'filename:.htpasswd',
                          'DB Credentials': 'filename:.env DB_USERNAME NOT homestead',
                          'Mail Credential': 'filename:.env MAIL_HOST=smtp.gmail.com',
                          '.git Credentials': 'filename:.git-credentials',
                          'PT_TOKEN': 'PT_TOKEN language:bash',
                          '.bashrc': 'filename:.bashrc password',
                          'mailchimp': 'filename:.bashrc mailchimp',
                          '.bash_profile aws': 'filename:.bash_profile aws',
                          'AWS RDS': 'rds.amazonaws.com password',
                          'forecast.io API': 'extension:json api.forecast.io',
                          'mongolab': 'extension:json mongolab.com',
                          'mongolab': 'extension:yaml mongolab.com',
                          'jsforce': 'jsforce extension:js conn.login',
                          'salesforce username': 'SF_USERNAME salesforce',
                          'tugboat': 'filename:.tugboat NOT _tugboat',
                          'HEROKU API KEY': 'HEROKU_API_KEY language:shell',
                          'HEROKU API KEY': 'HEROKU_API_KEY language:json',
                          'netrc': 'filename:.netrc password',
                          '_netrc': 'filename:_netrc password',
                          'oauth_token': 'filename:hub oauth_token',
                          'robomongo': 'filename:robomongo.json',
                          'filezilla': 'filename:filezilla.xml Pass',
                          'recentservers': 'filename:recentservers.xml Pass',
                          'config': 'filename:config.json auths',
                          'idea14': 'filename:idea14.key',
                          'irc_pass': 'filename:config irc_pass',
                          'connections.xml': 'filename:connections.xml',
                          'express.conf file': 'filename:express.conf path:.openshift',
                          '.pgpass file': 'filename:.pgpass',
                          'proftpdpasswd file': 'filename:proftpdpasswd',
                          'ventrilo_srv.ini': 'filename:ventrilo_srv.ini',
                          'WFClient': '[WFClient] Password= extension:ica',
                          'server.cfg': 'filename:server.cfg rcon password',
                          'JEKYLL_GITHUB_TOKEN': 'JEKYLL_GITHUB_TOKEN',
                          '.bash_history': 'filename:.bash_history',
                          '.cshrc': 'filename:.cshrc',
                          '.history file': 'filename:.history',
                          '.sh_history': 'filename:.sh_history',
                          'sshd_config': 'filename:sshd_config',
                          'dhcpd.conf': 'filename:dhcpd.conf',
                          'prod.exs': 'filename:prod.exs NOT prod.secret.exs',
                          'prod.secret.exs file': 'filename:prod.secret.exs',
                          'configuration.php file': 'filename:configuration.php JConfig password',
                          'config.php file': 'filename:config.php dbpasswd',
                          'config.php file': 'filename:config.php pass',
                          'sites databases password': 'path:sites databases password',
                          'shodan_api_key': 'shodan_api_key language:python',
                          'shodan_api_key': 'shodan_api_key language:shell',
                          'shodan_api_key': 'shodan_api_key language:json',
                          'shodan_api_key': 'shodan_api_key language:ruby',
                          'shadow file': 'filename:shadow path:etc',
                          'passwd file': 'filename:passwd path:etc',
                          'avastlic': 'extension:avastlic "support.avast.com"',
                          'dbeaver-data-sources.xm': 'filename:dbeaver-data-sources.xml',
                          'sftp-config.json': 'filename:sftp-config.json',
                          '.esmtprc': 'filename:.esmtprc password',
                          'googleusercontent': 'extension:json googleusercontent client_secret',
                          'HOMEBREW_GITHUB_API_TOKEN': 'HOMEBREW_GITHUB_API_TOKEN language:shell',
                          'xoxp or xoxb': 'xoxp OR xoxb',
                          '.mlab.com': '.mlab.com password',
                          'logins.json': 'filename:logins.json',
                          'CCCam.cfg': 'filename:CCCam.cfg',
                          'config': 'msg nickserv identify filename:config',
                          'settings.py': 'filename:settings.py SECRET_KEY',
                          'secrets.yml': 'filename:secrets.yml password',
                          'master.key': 'filename:master.key path:config',
                          'deployment-config.json': 'filename:deployment-config.json',
                          'ftpconfig': 'filename:.ftpconfig',
                          '.remote-sync.json': 'filename:.remote-sync.json',
                          'sftp.json': 'filename:sftp.json path:.vscode',
                          'WebServers.xml': 'filename:WebServers.xml',
                          'S3 bucket': 'bucket_name',
                          'S3 Bucket': 'S3_bucket',
                          'S3 Endpoint': 'S3_endpoint',
                          'AWS Accounts list': 'list_aws_accounts',
                          'AWS S3 Bucket URL': 's3.amazonaws.com',
                          'AWS S3 Bucket': 'S3://',
                          'OKTA API TOKEN': 'OKTA_API_TOKEN',
                          'API HOST': 'API_HOST',
                          'GHA USER TOKEN': 'GHA_USER_TOKEN',
                          'HEROKU_API_TOKEN': 'HEROKU_API_TOKEN',
                          'github.io Page': 'github.io',
                          'OTP': 'otp',
                          'SSH2 Auth Password': 'ssh2_auth_password',
                          'JDBC': 'JDBC',
                          'connectionstring': 'connectionstring',
                          'login-singin': 'login-singin',
                          'jenkins': 'jenkins',
                          'key-keys': 'key-keys',
                          'POSTGRES Password': 'POSTGRES_PASSWORD',

                          }
        self.patterns = {'Private Key': ["-{5}BEGIN (EC|RSA|DSA|OPENSSH) PRIVATE KEY-{5}"], 'amazon_secret_access_key': ["[0-9a-zA-Z/+]{40}"],
                         'google_oauth_api_id': ['[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'],
                         'mailgun_api_key': ['key-[0-9a-zA-Z]{32}'],
                         'mailchimp_api_key': ['0-9a-f]{32}-us[0-9]{1,2}'],
                         'slack_api_token': ['(xox[pboa]\-[0-9]{12}\-[0-9]{11}\-[0-9]{12}\-[a-z0-9]{32})'],
                         'slack_webhook': ['https:\/\/hooks.slack.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}'],
                         'Github_token': ['[0-9a-fA-F]{40}'],
                         'access_key': ['[0-9a-fA-F]{40}', '[0-9a-fA-F]{20}', '[0-9a-fA-F]{32}', '[^A-Za-z0-9/+=][A-Za-z0-9/+=]{40}[^A-Za-z0-9/+=]'],
                         'aws_secret_key': ['A-Za-z0-9/+=]{40}'],
                         'api_key': ['[0-9a-fA-F]{32}']}

        self.alerts = []

    # login to GitHub through the given token
    def login(self):

        try:
            self.g = Github(self.ACCESS_TOKEN)
            user = self.g.get_user()
            print("\n[++] Logged in successfully as " +
                  str(user.name) + "....\n")
            return self.g
        except Exception as E:
            return False

    def check_if_org_exists(self):
        invalid_targets = []

        for target in self.targets:
            try:
                try:
                    target = self.g.get_organization(target)
                except:
                    target = self.g.get_user(target)
            except:
                invalid_targets.append(target)
                pass

        if len(invalid_targets) == 0:
            return True
        else:
            return False

    # search github remotely function
    def searchGithubRemotely(self, target):

        check_calls = False

        while True:
            rate_limit = self.g.get_rate_limit()
            rate = rate_limit.search
            if rate.remaining == 0:
                print(
                    f'\n [**] You have 0/{rate.limit} API calls remaining. Reset time: {rate.reset}, we have to sleep for a while')
                time.sleep(5)
            else:
                break

        patterns = self.patterns.items()

        for pattern in patterns:

            result_code, result_commit = self.searchGithub(pattern[0], target)

            if result_code:
                try:
                    final_result = self.analyzeResult(
                        result_code, pattern[1], pattern[0], 'Code')
                except:
                    pass

            if result_commit:
                try:
                    final_result = self.analyzeResult(
                        result_commit, pattern[1], pattern[0], 'Commit')
                except:
                    pass

    def searchGithubRandomPattern(self, target):
        random_pattern_results = {}
        for ran in self.key_hacks.items():
            while True:
                try:
                    ran_query = f'"{ran[1]}" in:file org:' + target
                    ran_result = self.g.search_code(ran_query, order='desc')
                    time.sleep(2)
                    break
                except:
                    pass
            while True:
                try:
                    for x in ran_result:
                        while True:
                            print(Fore.RED)
                            print('-------------------------\n')
                            print('[--] Possible ' + ran[0] + ', Found ....')
                            try:
                                print("[--] URL : " + x.html_url + '\n')
                                self.alerts.append(
                                    {'name': ran[0], 'url': x.html_url})
                                time.sleep(1)
                                break
                            except:
                                pass
                    break
                except:
                    pass
    # it searches inside the code through GitHub API

    def searchGithub(self, keyword, target):

        try:
            query = f'"{keyword}" in:file org:' + target
            code_result = self.g.search_code(query, order='desc')
            time.sleep(2)

            commit_query = f'"{keyword}"  org:' + target
            commit_result = self.g.search_commits(commit_query)
            time.sleep(2)

        except:
            time.sleep(2)
            pass

        return code_result, commit_result

        # it analyze the gathered results by GitHub API

    def analyzeResult(self, result, reg, pattern_name, search_type):

        max_size = 100

        if result.totalCount > max_size:
            result = result[:max_size]

        if search_type == 'Code':
            for file in result:
                decoded_file = str(file.decoded_content)
                for x in reg:
                    check = re.search(x, decoded_file)
                    if check:
                        print(Fore.RED)
                        print('-------------------------\n')
                        print('[--] Possible ' + pattern_name +
                              ', Found on Code ....')
                        print("[--] URL : " + file.html_url + '\n')
                        self.alerts.append(
                            {'name': pattern_name, 'url': file.html_url})
            time.sleep(2)

        elif search_type == 'Commit':

            for file in result:
                print(Fore.RED)
                print('-------------------------\n')
                print('[--] Possible ' + pattern_name +
                      ', Found on Commit ....')
                print("[--] URL : " + file.html_url + '\n')
                self.alerts.append(
                    {'name': pattern_name, 'url': file.html_url})
            time.slee(2)

    # scanning org's members to find leaks
    def scanMemebers(self, target):

        try:
            target = self.g.get_organization(target)
            members = target.get_members()
            print('\n[++] Found ' + str(members.totalCount) +
                  ' members, scanning for keys .....\n')
            for member in members:
                print(Fore.GREEN)
                print('[++] ' + member.login)

                while True:

                    try:

                        us = self.g.get_user(member.login)
                        user_repos = us.get_repos()
                        break

                    except Exception as E:

                        pass

                if user_repos.totalCount > 0:

                    self.searchGithubRemotely(member.login)

                else:

                    pass

                time.sleep(0.2)

        except:
            pass

    def main(self):

        if self.login() != False:

            if self.check_if_org_exists() == True:

                for target in self.targets:
                    print(Fore.GREEN)
                    print('\n[++] Scanning ' + target +
                          ' for sensitve data leaks ' + ' .....\n\n')
                    self.searchGithubRandomPattern(target)
                    self.searchGithubRemotely(target)
                    print(Fore.GREEN)
                    print("\n[++] Finished " + target +
                          " scanning " + ' .....')
                    if self.scan_memebers == True:
                        self.scanMemebers(target)

                    time.sleep(10)

                    with open(target+'-github-report.json', 'w') as file:
                        alerts_list = {'alerts': self.alerts}
                        json.dump(alerts_list, file, indent=4)
                    print(Fore.GREEN)
                    print('\n \n[++] The result is saved under filename: ' +
                          str(target)+'-github-report.json')

                    print('\n[++] Done, existing ..... \n')

            else:
                print(Fore.RED)
                print('\n\n[--] We clould not find the org/user ...\n\n')

        else:

            print(
                '\n[--] We are not able to login using the provided GitHub Login .. \n')


print(Fore.GREEN)
banner = pyfiglet.figlet_format(
    "GH  S c a n n e r T o o l", width=130,  justify='center')

print('\n \n'+banner)
print('Developed By @Alifathi-h1 \n\n '.center(90))


parser = argparse.ArgumentParser(
    description='GH Scanner Tool is written in Python3 that scans Organization/User repositories for leaks such as GitHub Token, AWS Access Keys and more. \n\n')
parser.add_argument(
    '-o', '--org', help='Organization name or user account', required=True)
parser.add_argument("-sM", "--include-members",
                    help="scan organization's members", action="store_true")
args = parser.parse_args()


org = args.org
members_scan = args.include_members


github_scanner = GithubScanner([org], members_scan)
github_scanner.main()
