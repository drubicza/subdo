import requests, time, json, hashlib, argparse, sys
from urllib.parse import parse as urllib
from requests.packages import urllib3
from urllib.parse import urlparse
from fake_useragent import UserAgent
from bs4 import BeautifulSoup
Logo = '   _____       __        __    \n  / ___/__  __/ /_  ____/ /___ \n  \\__ \\/ / / / __ \\/ __  / __ \\   \n ___/ / /_/ / /_/ / /_/ / /_/ /\n/____/\\__,_/_.___/\\__,_/\\____/'
Inform = 'CreateBy : JUNIOR404'
Help = '\x1b[0m stop ctrl+c'
urllib3.disable_warnings()
ua = UserAgent()
header = {'User-Agent': ua.chrome}

def parse_args():
    parser = argparse.ArgumentParser(epilog=('\tExample: \r\npython ' + sys.argv[0] + ' -d baidu.com'))
    parser.add_argument('-d', '--domain', help='Domain name to enumerate subdomains of', required=True)
    parser.add_argument('-o', '--output', help='Output file name , By default, the domain name is the file_name.txt', action='store_true')
    parser.add_argument('-html', '--html', help='Output html, the domain name is the file_name.html', action='store_true')
    return parser.parse_args()


def get_domain_from_crt(domain):
    part_subdomains = []
    url = 'https://crt.sh/?q=%.' + domain
    try:
        data_raw = requests.get(url, headers=header, verify=False)
        data_content = data_raw.content.decode('utf-8', 'ignore')
        data_html = BeautifulSoup(data_content, 'html.parser')
        html_tds = data_html.findAll('td', {'class': 'outer'})
        html_trs = html_tds[1].findAll('tr')
    except Exception as e:
        try:
            print(e)
            return
        finally:
            e = None
            del e

    for html_tr in html_trs:
        try:
            html_tr_ths = html_tr.findAll('td')
            subdomain = html_tr_ths[4].get_text()
            if subdomain != None:
                if subdomain != '':
                    pass
            if subdomain not in part_subdomains:
                part_subdomains.append(subdomain)
        except:
            pass

    return part_subdomains


def get_domain_from_google_transparencyreport(domain):
    part_subdomains = []
    nxet_page_key = ''
    while 1:
        if nxet_page_key != None:
            if nxet_page_key == '':
                api_url = 'https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?domain={domain}&include_expired=false&include_subdomains=true'.format(domain=domain)
            else:
                api_url = 'https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch/page?p={p}'.format(p=nxet_page_key)
            try:
                data_raw = requests.get(api_url, headers=header, verify=False, timeout=10)
            except Exception as e:
                try:
                    print(e)
                    return part_subdomains
                finally:
                    e = None
                    del e

            data_content = data_raw.content.decode('utf-8', 'ignore').replace(")]}'", '')
            data_json = json.loads(data_content)
            nxet_page_key = data_json[0][3][1]
            data_json = data_json[0][1]
            for domain_raw in data_json:
                if domain_raw[1] not in part_subdomains:
                    part_subdomains.append(domain_raw[1])

    return part_subdomains


def get_domain_from_dnsdumpster(domain):
    part_subdomains = []
    header = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:63.0) Gecko/20100101 Firefox/63.0',
     'Referer':'https://dnsdumpster.com/'}
    post_data = {'csrfmiddlewaretoken':'3JELokv01c2aMvS3x5hoBcBmOn7ZMmfk',
     'targetip':domain}
    cookie = {'csrftoken': '3JELokv01c2aMvS3x5hoBcBmOn7ZMmfk'}
    try:
        data_raw = requests.post('https://dnsdumpster.com/', headers=header, data=post_data, cookies=cookie, verify=False)
        data_content = data_raw.content.decode('utf-8', 'ignore')
        data_html = BeautifulSoup(data_content, 'html.parser')
        html_tds = data_html.findAll('td', {'class': 'col-md-4'})
    except Exception as e:
        try:
            print(e)
            return
        finally:
            e = None
            del e

    for html_td in html_tds:
        domain_temp = html_td.get_text().strip()
        if domain_temp != '':
            if domain_temp != None:
                if domain_temp.find('\n') != -1:
                    domain_temp = domain_temp[:domain_temp.find('\n')]
                if domain in domain_temp:
                    if domain_temp not in part_subdomains:
                        part_subdomains.append(domain_temp)

    return part_subdomains


def get_domain_from_natcraft(domain):
    part_subdomains = []
    page_count = 1
    have_content = True
    last_domain = ''
    while have_content:
        response = requests.get('https://searchdns.netcraft.com/', headers=header, verify=False, timeout=10)
        temp_headers = response.headers
        if 'set-cookie' in temp_headers:
            temp_cookie = temp_headers['set-cookie']
            temp_cookies = dict()
            temp_cookies_list = temp_cookie[0:temp_cookie.find(';')].split('=')
            temp_cookies[temp_cookies_list[0]] = temp_cookies_list[1]
            temp_cookies['netcraft_js_verification_response'] = hashlib.sha1(urllib.unquote(temp_cookies_list[1]).encode('utf-8')).hexdigest()
        url = 'https://searchdns.netcraft.com/?host=.{domain}&last={last_domain}&from={page}&restriction=site%20contains&position='.format(domain=domain, page=page_count, last_domain=last_domain)
        last_domain = ''
        try:
            data_raw = requests.get(url, headers=header, cookies=temp_cookies, verify=False, timeout=10)
            data_content = data_raw.content.decode('utf-8', 'ignore')
            data_html = BeautifulSoup(data_content, 'html.parser')
        except Exception as e:
            try:
                print(e)
                return part_subdomains
            finally:
                e = None
                del e

        try:
            html_divs = data_html.findAll('div', {'class': 'blogbody'})
            html_ps = html_divs[1].findAll('p')
            html_ps_a = html_ps[1].find('a')
            last_domain = html_ps_a.get('href')[html_ps_a.get('href').find('last=') + 5:html_ps_a.get('href').find('&from=')]
        except Exception as e:
            try:
                have_content = False
            finally:
                e = None
                del e

        if last_domain == '':
            have_content = False
        try:
            html_table = data_html.find('table', {'class': 'TBtable'})
            html_as = html_table.findAll('a', {'rel': 'nofollow'})
        except Exception as e:
            try:
                print(e)
                continue
            finally:
                e = None
                del e

        for html_a in html_as:
            subdomian = html_a.get_text()
            if subdomian != '':
                if subdomian not in part_subdomains:
                    part_subdomains.append(subdomian)

        page_count += 20
        time.sleep(3)

    return part_subdomains


def get_domain_from_threatcrowd(domain):
    part_subdomains = []
    url = 'https://www.threatcrowd.org/domain.php?domain=' + domain
    try:
        data_raw = requests.post(url, headers=header, verify=False, timeout=10)
        data_content = data_raw.content.decode('utf-8', 'ignore')
        data_html = BeautifulSoup(data_content, 'html.parser')
        html_div = data_html.find('div', {'id': 'collapseSub'})
        html_table = html_div.find('table')
        html_as = html_table.findAll('a')
    except Exception as e:
        try:
            print(e)
            return
        finally:
            e = None
            del e

    for html_a in html_as:
        domain_temp = html_a.get_text().strip()
        if domain_temp != '':
            if domain_temp != None:
                if domain_temp not in part_subdomains:
                    if domain in domain_temp:
                        part_subdomains.append(domain_temp)

    return part_subdomains


def get_domain_from_virustotal(domain):
    part_subdomains = []
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    params = {'apikey':'123',  'domain':domain}
    try:
        data_raw = requests.get(url, headers=header, params=params, verify=False, timeout=10)
    except Exception as e:
        try:
            print(e)
            return
        finally:
            e = None
            del e

    data_content = data_raw.content.decode('utf-8', 'ignore')
    data_json = json.loads(data_content)
    for subdomian in data_json['subdomains']:
        if subdomian not in part_subdomains:
            part_subdomains.append(subdomian)

    return part_subdomains


def get_domain_from_ask(domain):
    part_subdomains = []
    have_content = True
    page_count = 1
    while 1:
        if have_content:
            url = 'https://www.ask.com/web?o=0&l=dir&qo=pagination&q=site:*.{domain}&qsrc=998&page={page}'.format(domain=domain, page=page_count)
            try:
                data_raw = requests.get(url, headers=header, verify=False, timeout=10)
                data_content = data_raw.content.decode('utf-8', 'ignore')
                data_html = BeautifulSoup(data_content, 'html.parser')
                html_ps = data_html.findAll('p', {'class': 'PartialSearchResults-item-url'})
            except Exception as e:
                try:
                    print(e)
                    return part_subdomains
                finally:
                    e = None
                    del e

            if len(html_ps) == 0:
                have_content = False
                continue
                for html_p in html_ps:
                    url = 'http://' + html_p.get_text()
                    parsed = urlparse(url)
                    parsed_domain = parsed.netloc
                    if parsed_domain not in part_subdomains:
                        part_subdomains.append(parsed_domain)

            page_count += 1

    return part_subdomains


def get_domain_from_baidu(domain):
    part_subdomains = []
    have_content = True
    page_count = 0
    while 1:
        if page_count < 200:
            url = 'https://www.baidu.com/s?wd=site%3A{domain}&pn={page}'.format(domain=domain, page=page_count)
            try:
                data_raw = requests.get(url, headers=header, verify=False, timeout=10)
                data_content = data_raw.content.decode('utf-8', 'ignore')
                data_html = BeautifulSoup(data_content, 'html.parser')
                html_as = data_html.findAll('a', {'class': 'c-showurl'})
            except Exception as e:
                try:
                    print(e)
                    return part_subdomains
                finally:
                    e = None
                    del e

            temp_page = []
            for html_a in html_as:
                parsed = urlparse(html_a.get_text())
                parsed_domain = parsed.netloc
                if parsed_domain not in part_subdomains:
                    if parsed_domain != '':
                        part_subdomains.append(parsed_domain)

            page_count += 10

    return part_subdomains


def get_domain_from_bing(domain):
    part_subdomains = []
    have_content = True
    page_count = 0
    while 1:
        if page_count < 200:
            url = 'https://cn.bing.com/search?q=site%3A{domain}&qs=n&form=QBRE&sp=-1&pq=site%3A{domain}&sc=2-11&sk=&cvid=C1A7FC61462345B1A71F431E60467C43&toHttps=1&redig=3FEC4F2BE86247E8AE3BB965A62CD454&pn=2&first={page}&FROM=PERE'.format(domain=domain, page=page_count)
            response = requests.get('http://cn.bing.com/', headers=header)
            try:
                data_raw = requests.get(url, headers=header, verify=False, cookies=(response.cookies.get_dict()), timeout=10)
                data_content = data_raw.content.decode('utf-8', 'ignore')
                data_html = BeautifulSoup(data_content, 'html.parser')
                html_divs = data_html.findAll('div', {'class': 'b_attribution'})
            except Exception as e:
                try:
                    print(e)
                    return part_subdomains
                finally:
                    e = None
                    del e

            temp_page = []
            for html_div in html_divs:
                html_cite = html_div.find('cite')
                parsed = urlparse(html_cite.get_text())
                parsed_domain = parsed.netloc
                if parsed_domain not in part_subdomains:
                    if parsed_domain != '':
                        part_subdomains.append(parsed_domain)

            page_count += 10

    return part_subdomains


def get_domain_from_so(domain):
    part_subdomains = []
    have_content = True
    page_count = 0
    while page_count < 20:
        url = 'https://www.so.com/s?q=site%3A{domain}&pn={page}&psid=8ce82e610522aff397e88b1f2604330f&src=srp_paging&fr=none'.format(domain=domain, page=page_count)
        try:
            data_raw = requests.get(url, headers=header, verify=False, timeout=10)
            data_content = data_raw.content.decode('utf-8', 'ignore')
            data_html = BeautifulSoup(data_content, 'html.parser')
            html_ps = data_html.findAll('p', {'class': 'res-linkinfo'})
        except Exception as e:
            try:
                print(e)
                return part_subdomains
            finally:
                e = None
                del e

        for html_p in html_ps:
            html_cite = html_p.find('cite')
            parsed = urlparse('http://' + html_cite.get_text())
            parsed_domain = parsed.netloc
            if parsed_domain.find('>') != -1:
                parsed_domain = parsed_domain[0:parsed_domain.find('>')]
            if parsed_domain not in part_subdomains:
                if parsed_domain != '':
                    part_subdomains.append(parsed_domain)

        page_count += 1

    return part_subdomains


def get_domain_from_google(domain):
    part_subdomains = []
    have_content = True
    page_count = 0
    while have_content and page_count < 200:
        url = 'https://www.google.com/search?q=site:{domain}&ei=wac1Xdu_KYnFz7sPx62wwAU&start={page}&sa=N&ved=0ahUKEwibpIy4v8jjAhWJ4nMBHccWDFg43gIQ8tMDCEE&biw=2645&bih=1059'.format(domain=domain, page=page_count)
        try:
            data_raw = requests.get(url, headers=header, verify=False, timeout=10)
            data_content = data_raw.content.decode('utf-8', 'ignore')
            data_html = BeautifulSoup(data_content, 'html.parser')
            html_cites = data_html.findAll('cite', {'class': 'iUh30'})
        except Exception as e:
            try:
                print(e)
                return part_subdomains
            finally:
                e = None
                del e

        if len(html_cites) == 0:
            have_content = False
            return part_subdomains
        for html_cite in html_cites:
            parsed = urlparse(html_cite.get_text())
            parsed_domain = parsed.netloc
            if parsed_domain.find(u'\u203a') != -1:
                parsed_domain = parsed_domain[0:parsed_domain.find(u'\u203a')]
            if parsed_domain not in part_subdomains:
                if parsed_domain != '':
                    part_subdomains.append(parsed_domain.strip())

        page_count += 10
        time.sleep(5)

    return part_subdomains


def GetDoaminIP(domain):
    try:
        from socket import gethostbyname
        ip_list = gethostbyname(domain)
        return ip_list
    except Exception as e:
        try:
            return ''
        finally:
            e = None
            del e


def GetDomainStatu(domain):
    import requests
    header = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:63.0) Gecko/20100101 Firefox/63.0'}
    try:
        result = requests.get(('http://{0}/'.format(domain)), headers=header, timeout=10)
    except:
        return ''
        return str(result.status_code)


def GetUrlTitle(url):
    try:
        data_raw = requests.get(url, headers=header, verify=False, timeout=10)
        data_content = data_raw.content.decode('utf-8', 'ignore')
        data_html = BeautifulSoup(data_content, 'html.parser')
        return data_html.title.get_text().strip()
    except:
        return ''


def subdomain_finder(domain):
    subdomains = []
    temp_subdomains = []
    try:
        temp_subdomains.append(get_domain_from_crt(domain))
        temp_subdomains.append(get_domain_from_dnsdumpster(domain))
        temp_subdomains.append(get_domain_from_threatcrowd(domain))
        temp_subdomains.append(get_domain_from_virustotal(domain))
        temp_subdomains.append(get_domain_from_natcraft(domain))
        temp_subdomains.append(get_domain_from_google_transparencyreport(domain))
        temp_subdomains.append(get_domain_from_ask(domain))
        temp_subdomains.append(get_domain_from_baidu(domain))
        temp_subdomains.append(get_domain_from_bing(domain))
        temp_subdomains.append(get_domain_from_so(domain))
        temp_subdomains.append(get_domain_from_google(domain))
    except KeyboardInterrupt:
        pass
    except Exception as e:
        try:
            print(e)
        finally:
            e = None
            del e

    for temp_subdomain in temp_subdomains:
        if not temp_subdomain == None:
            if temp_subdomain == []:
                continue
                for subdomain_raw in temp_subdomain:
                    subdomain = subdomain_raw.strip()
                    subdomain = subdomain_raw.strip('.')
                    if subdomain.find('*') != -1:
                        subdomain = subdomain[2:]
                    if subdomain is not None:
                        if subdomain != '':
                            if domain in subdomain:
                                if subdomain not in subdomains:
                                    subdomains.append(subdomain)

    return subdomains


def process_domains(domain, subdomains, mode='html'):
    temp_subdomains = list(set(subdomains))
    temp_subdomains.sort()
    if mode == 'html':
        print('A total of {0} subdomains need to be processed\n'.format(str(len(subdomains))))
        with open((domain.replace('.', '_') + '.html'), 'w', encoding='utf-8') as (fobject):
            html = '<!DOCTYPE html>\n<html>\n<head>\n<title>{title}</title>\n'.format(title=domain)
            html += '<link rel="stylesheet" href="./css/style.css">\n</head>'
            html += '<body>\n<p class="domain" align="center">{domain}</p><table class="imagetable" align="center">\n'.format(domain=domain)
            html += '<tr>\n<th>id</th>\n<th>subdomain</th>\n<th>site</th>\n<th>title</th>\n<th>ip</th>\n<th>statu</th>\n</tr>'
            fobject.write(html)
            domain_id = 1
            for subdomain in temp_subdomains:
                domain_ip = GetDoaminIP(subdomain)
                domain_statu = GetDomainStatu(subdomain)
                domain_url = 'http://{0}'.format(subdomain)
                domain_title = GetUrlTitle(domain_url)
                print(' {id} : {subdomain} {title} {ip} {statu} '.format(id=(str(domain_id)), subdomain=subdomain, title=domain_title, ip=domain_ip, statu=domain_statu))
                fobject.write('<tr>\n<td>{id}</td>\n<td>{subdomain}</td>\n<td>{site}</td>\n<td>{title}</td>\n<td>{ip}</td>\n<td>{statu}</td>\n</tr>'.format(id=(str(domain_id)), subdomain=subdomain, site='<a target="_blank" href="{link}">{name}</a>'.format(link=domain_url, name=subdomain), title=domain_title, ip=domain_ip, statu=domain_statu))
                domain_id += 1

            fobject.write('</table>\n</body>\n</html>')
        print('\nOutput to file: {0}\n'.format(domain.replace('.', '_') + '.html'))


if __name__ == '__main__':
    print(Logo)
    print(Inform)
    args = parse_args()
    domain = args.domain
    print('\x1b[91m \ndomain: {0}\n'.format(domain))
    print(Help)
    subdomains = subdomain_finder(domain)
    print('\nFound a total of {0} subdomains\n'.format(str(len(subdomains))))
    for subdomain in subdomains:
        print(subdomain)

    if args.output == True:
        output_name = domain.replace('.', '_') + '.txt'
        with open(output_name, 'w', encoding='utf-8') as (file_object):
            for subdomain in subdomains:
                file_object.write(subdomain + '\n')

        print('\nOutput to file: {0}\n'.format(output_name))
if args.html == True:
    process_domains(domain, subdomains, 'html')
