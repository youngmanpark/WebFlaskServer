import json
import socket
import datetime
import ssl
import urllib.request
from urllib.parse import urlparse, parse_qs
from selenium import webdriver
from selenium.common import NoSuchElementException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

import requests
from bs4 import BeautifulSoup
import re
import sys
from urllib import parse
from urllib.request import urlopen
import time
import os
from fpdf import FPDF
from webdriver_manager.chrome import ChromeDriverManager


def return_json_data(url):
    #데이터 평문 전송 취약점
    def check_encryption_support(url):
        url = url.split('/')[0]
        module_name = "Cleartext Transmission " #모듈 네임
        description="Whether or not the server verifies communication between the server and the client"
        # description="서버와 클라이언트 간 통신 시 데이터의 암호화 여부 점검"
        purpose="To prevent the risk of information leakage due to insufficient data encrypted transmission during communication between the server and the client"
        # purpose="서버와 클라이언트 간 통신 시 데이터의 암호화 전송 미흡으로 정보 유출의 위험을 방지하고자 함"
        security_threat ="Since data communication on the web is mostly text-based, information can be stolen and stolen through simple sniffing if an encryption process is not implemented between the server and the client."
        # security_threat ="웹상의 데이터 통신은 대부분 텍스트 기반으로 이루어지기 때문에 서버와 클라이언트 간에 암호화 프로세스를 구현하지 않으면 간단한 도청(Sniffing)을 통해 정보를 탈취 및 도용할 수 있음"
        contents = "" #결과 내용을 저장할 변수
        is_cve = "Safe" #스캔 결과의 CVE(Common Vulnerabilties and Exposures) 상태
        ip = socket.gethostbyname(url)

        port=80
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)  # 타임아웃 설정 (2초)
            sock.connect((ip, port))

            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                # SSL/TLS 암호화가 적용된 경우 실행될 코드
                print(f"Port {port} supports encryption (TLS/SSL).")
                # 인증서 정보나 기타 암호화 관련 정보를 확인하고 싶은 경우에는 ssock 변수를 사용합니다.
                print(ssock.version())
        except (socket.timeout, ConnectionRefusedError):
            contents+=(f"Port {port} is closed or the connection timed out.")
        except ssl.SSLError:
            # print(f"Port {port} does not support encryption (TLS/SSL).")
            contents+=f"Port {port} does not support encryption (TLS/SSL)."
            is_cve='risk'

        return (module_name, description,purpose, security_threat,contents.strip(),is_cve)


    # 포트 리스트를 반복하며 각 포트에 대해 암호화 지원 여부를 확인합니다.



    #관리자 페이지 노출
    def adpage(domain):
        module_name = "Admin Page" #모듈 네임
        description = "Check whether the admin page and menu access is possible with an easy-to-infer URL"
        # description = "유추하기 쉬운 URL로 관리자 페이지 및 메뉴 접근의 가능 여부 점검"
        purpose="To prevent unauthorized persons from accessing the admin menu by correcting the easy-to-understand names (admin, manager, etc.) of the admin page URL and website design errors"
        # purpose="관리자 페이지 URL이 유추하기 쉬운 이름(admin, manager 등) 및 웹 사이트 설계 오류를 수정하여 비인가자의 관리자 메뉴 접근을 방지하고자 함"
        security_threat="If the authority of the web administrator is exposed, not only the modification of the website but also the authority of the web server may be exposed depending on the degree of vulnerability."
        # security_threat="웹 관리자의 권한이 노출될 경우 웹 사이트의 변조뿐만 아니라 취약성 정도에 따라서 웹 서버의 권한까지도 노출될 수 있음"
        contents = "" #결과 내용을 저장할 변수
        is_cve = "Safe" #스캔 결과의 CVE(Common Vulnerabilties and Exposures) 상태

        page = ["/admin", "/manager", "/master", "/system", "/administart"] #예상되는 관리자 페이지 경로
        url = "http://" + domain
        for pages in page:
            try:
                req = urllib.request.urlopen(url + pages) #생성된 경로에 대한 요청 시도
                contents += (url+pages + " server exist\n") #content에 해당 페이지의 존재 여부 추가
                is_cve = "Risk" #CVE 상태를 RISK로 변환
            except: continue

        if is_cve == "Safe": #관리자페이 미존재
            contents += "no admin page found"

        return (module_name, description, purpose, security_threat, contents.strip(), is_cve)


    def get_header(domain):
        global req, header, dic, cve
        req = requests.get('http://'+domain) #주어진 도메인에 get요청 보내고 응답을 req에 저장
        header = req.headers #응답헤더 저장
        dic = {'server' : 'hidden', 'os' : 'hidden', 'lang' : 'hidden'}
        cve = {'server' : '', 'lang' : ''}
        if 'Server' in header:
            server=header['Server']
            s = server.split(' ')
            for i, a in enumerate(dic.keys()):
                dic[a] = s[i]
                if (len(s) < len(dic)):
                    break
        else:
            pass

    def check_cve(get_header): # CVE 를 확인하는 방법
        module_name = "Check CVE"
        description = "Common Vulnerabilities and Exposures (CVE) is a list of publicly known computer security flaws. CVE usually refers to a security flaw assigned a CVE ID number."
        # description = "CVE(Common Vulnerabilities and Exposures)는 공개적으로 알려진 컴퓨터 보안 결함 목록입니다. CVE는 보통 CVE ID 번호가 할당된 보안 결함을 뜻합니다."
        purpose = "It aims to standardize the way known vulnerabilities are identified. Standard IDs help security managers find and utilize technical information about specific threats from many different sources of CVE support information."
        # purpose = "알려진 취약점을 식별하는 방식을 표준화하는 데 목적이 있다. 표준 ID는 보안 관리자가 여러 다양한 CVE 지원 정보 소스에서 특정 위협에 대한 기술적 정보를 찾아 활용하도록 도움을 준다."
        security_threat = "A publicly known computer security flaw (CVE) based on header information from that server"
        # security_threat = "해당 서버의 헤더 정보를 바탕으로 공개적으로 알려진 컴퓨터 보안 결함(CVE)"
        contents = ""
        is_cve = "Safe"
        def cve1(key, contents, is_cve):
            r = requests.get('https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword='+str(dic[key]))
            # MITRE CVE 데이터베이스에서 CVE를 확인하기 위해 GET 요청
            soup = BeautifulSoup(r.text, 'html.parser')
            count_target = soup.find(class_="smaller") #CVE 개수 정보를 담고 있는 요소를 찾기
            cve[key] = count_target.find("b").text #해당 정보에 대한 CVE 개수를 추출
            list_result = str(soup.select("#TableWithRules")) #CVE 결과 테이블을 선택
            list_result = re.sub('<.+?>','',list_result,0).strip() # HTML 태그를 제거하고 앞뒤 공백 제거

            if len(list_result) > 26: #테이블의 존재여부 확인
                contents += 'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword='+str(dic[key])
                is_cve = "Risk"
            return contents, is_cve

        if dic['server'] != 'hidden': #서버 정보가 숨겨져 있지 않은 경우
            contents, is_cve = cve1('server', contents, is_cve)
        if dic['lang'] != 'hidden': #언어 정보가 숨겨져 있지 않은경우
            contents, is_cve = cve1('lang', contents, is_cve)
        if contents == "": #결과 내용이 비어있는경우
            contents = "no cve found"

        return (module_name, description, purpose, security_threat, contents.strip(), is_cve)



    def extract_links_from_url(url):

        global links
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        links = []
        for link in soup.find_all('a'):
            href = link.get('href')
            if href:
                links.append(href)

        return links

    #xss 취약점
    def dicxss(url):
        module_name = "XSS Injection"
        description = "Check for cross-site scripting vulnerabilities in your website"
        # description = "웹 사이트 내 크로스사이트 스크립팅 취약점 존재 여부 점검"
        purpose=" Block malicious script execution by removing cross-site scripting vulnerabilities in websites"
        # purpose=" 웹 사이트 내 크로스사이트 스크립팅 취약점을 제거하여 악성 스크립트의 실행을 차단"
        security_threat="If filtering of user input values ​​is not properly performed in web applications, an attacker inserts malicious scripts (Javascript, VBScript, ActiveX, Flash, etc.) Cookies (session) can be hijacked and stolen or redirected to malicious code distribution sites"
        # security_threat=" 웹 애플리케이션에서 사용자 입력 값에 대한 필터링이 제대로 이루어지지 않을 경우, 공격자는 사용자 입력 값을 받는 게시판, URL 등에 악의적인 스크립트(Javascript, VBScript, ActiveX, Flash 등)를 삽입하여 게시글이나 이메일을 읽는 사용자의 쿠키(세션)를 탈취하여 도용하거나 악성코드 유포 사이트로 Redirect 할 수 있음"
        contents = "Not detected WEAKNESS about XSS"
        is_cve = "Safe"

        url = url.split('/')[0]
        url = "http://" + url
        # getLinks(url) #주어진 URL에서 모든 페이지 링크 추출
        lst = list(extract_links_from_url(url)) #추출된 모든 페이지 링크를 리스트로 담음




        dic = {}
        d = 0
        for i in lst:
            check = parse.urlparse(lst[int(d)]) #현재 링크를 파싱하여 URL 구성요소를 추출



            if check.query: #파싱된 URL에 쿼리 파라미터가 있는지 확인
                dic.update(parse.parse_qs(check.query)) #쿼리 파라미터와 값을 dic에 담음(parse_qs 함수는 쿼리 문자열을 파싱하여 딕셔너리로 반환)

            d += 1

        fname = "payload2.txt" #xss 공격에 사용할 페이로드가 포함된 파일 이름
        with open(fname,'rt',encoding='UTF*') as f:
            content = f.readlines() #파일의 모든 줄을 읽어들임
        payloads = [x.strip() for x in content] #읽어들인 줄에서 양쪽 공백을 제거하고 payloads 리스트에 저장
        vuln = []

        for payload in payloads:

            for t in dic.keys(): #쿼리 파라미터 순회
                xss_url = url + "?" + t + "=" +"/>"+ payload #현재 키와 페이로드를 사용하여 xss 취약한 url 생성
                try:
                    r = requests.get(xss_url) #생성한 취약한 url에 get요청
                    if payload.lower() in r.text.lower(): #응답 텍스트에 소문자로 변환한 페이로드가 포함되어 있는지 확인
                        if (payload not in vuln): #취약점 리스트에 현재 페이로드가 이미 존재하는지 확인
                            vuln.append(payload) #취약점 리스트에 현재 페이로드 추가
                    else:
                        continue
                except requests.exceptions.ReadTimeout:
                    is_cve="Safe"
                    continue
        if vuln: #취약점 존재한다면
            tmp_contents = "\n".join(vuln) #취약점 리스트의 요소를 줄바꿈으로 구분하여 하나의 문자열로 만듬
            contents += str(tmp_contents) #결과 내용에 취약점 문자열 추가
            is_cve = "Risk" #취약점 존재시 risk로 변환

        return (module_name, description, purpose, security_threat, contents.strip(), is_cve)


    #sql Injection 취약점
    def sqltest(url):
        global is_cve
        module_name = "SQL Injection"
        description = "Checks for SQL injection vulnerabilities in web pages"
        # description = "웹 페이지 내 SQL 인젝션 취약점 존재 여부 점검"
        purpose="To prevent malicious database access and manipulation by blocking abnormal user input values ​​on interactive websites"
        # purpose="대화형 웹 사이트에 비정상적인 사용자 입력 값 허용을 차단하여 악의적인 데이터베이스 접근 및 조작을 방지하기 위함"
        security_threat="An attack that takes advantage of the weakness that website SQL queries are completed with user input values, and combines or executes abnormal SQL queries by tampering with input values. It is possible to manipulate the database abnormally by causing the developer to execute unexpected SQL statements."
        # security_threat="사용자의 입력 값으로 웹 사이트 SQL 쿼리가 완성되는 약점을 이용하며,입력 값을 변조하여 비정상적인 SQL 쿼리를 조합하거나 실행하는 공격. 개발자가 생각지 못한 SQL문을 실행되게 함으로써 데이터베이스를 비정상적으로 조작 가능함"
        contents = ""
        is_cve = "Safe"

        # chrome_options = Options()
        # chrome_options.add_experimental_option("detach", True)
        #
        # # 불필요한 에러 메시지 없애기
        # chrome_options.add_experimental_option("excludeSwitches", ["enable-logging"])

        # 드라이버 생성
        driver = webdriver.Chrome()
        # chrome_options = webdriver.ChromeOptions()
        # driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

        url="http://"+url+"/members/login"
        # url="http://"+url+"/login.php"


        def sqlinjection_tautologies():
            sql_ex = [" ' or 1=1 # ", " ' or 1=1 or ' '=' ", " ' or '1'='1' #"]
            return sql_ex

        def extract_input_ids(url):
            # GET 요청 보내기
            response = requests.get(url)

            # 응답의 HTML 내용 추출
            html_doc = response.text

            # BeautifulSoup 객체 생성
            soup = BeautifulSoup(html_doc, 'html.parser')

            # 모든 입력 태그 추출
            input_tags = soup.find_all('input')

            # 각 입력 태그의 id 추출
            ids = [tag.get('id') for tag in input_tags if tag.get('id')]



            return ids


        def find_input_param(URL):
            global password, username, search
            # 입력파라미터를 자동으로 불러옴
            for id in extract_input_ids(URL):
                s = "#{0}".format(id)
                pass_keys = ['pw', 'password', 'pwd']
                search_key = 'search'
                user_ = 'username'
                if any(key in s for key in pass_keys):
                    password = WebDriverWait(driver, 10).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, s))
                    )
                elif search_key in s:
                    search = WebDriverWait(driver, 10).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, s))
                    )

                elif user_ in s:
                    username = WebDriverWait(driver, 10).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, s))
                    )

        def check_login_suc():

            # 로그인 성공 여부 확인
            if driver.current_url == 'http://210.110.39.89/DVWA/index.php':
                # print('Detected WEAKNESS about Tautologies sql Injection!\n')
                is_cve='risk'
                return 'sql Injection risk',is_cve
            elif  driver.current_url == 'http://210.110.39.89/testboard/list.php':
                is_cve = 'risk'
                return 'sql Injection risk',is_cve
            elif driver.current_url == 'http://43.201.117.55':
                is_cve = 'risk'
                return 'sql Injection risk',is_cve
            else:
                is_cve='safe'
                return 'Not Detected WEAKNESS about sql Injection!',is_cve



        for s in sqlinjection_tautologies():
            driver.get(url)
            find_input_param(url)

            username.send_keys("admin")
            password.send_keys("fake"+s)
            password.send_keys(Keys.RETURN)
            # print("injection parameter: {0}".format(s))
            contents=check_login_suc()[0]
            is_cve=check_login_suc()[1]

        return (module_name, description, purpose, security_threat, contents.strip(), is_cve)

    def get_urldirectorypath(url):
        current_pagep = '\/[a-zA-Z0-9]*\.[a-zA-Z0-9]*$'
        path = re.sub(current_pagep, "", url)
        return path

    def return_souporhtml(url, str):
        r = requests.get(url).text
        soup = BeautifulSoup(r, 'html.parser')
        if(str=="soup"):
            return soup
        elif(str=="html"):
            return soup.text

    def regex_search(regex, str):
        p = re.compile(regex)
        s = p.search(str)
        return s

    def dicrec(url):
        module_name = "Directory Indexing"
        description = "Checking for directory indexing vulnerabilities in the web server"
        # description = "웹 서버 내 디렉터리 인덱싱 취약점 존재 여부 점검"
        purpose="Block exposure of unnecessary file information in a specific directory by removing directory indexing vulnerabilities"
        # purpose="디렉터리 인덱싱 취약점을 제거하여 특정 디렉터리 내 불필요한 파일 정보의 노출을 차단"
        security_threat=" A vulnerability that automatically displays a directory list when files of the initial page (index.html, home.html, default.asp, etc.) do not exist in a specific directory."
        # security_threat=" 특정 디렉터리에 초기 페이지 (index.html, home.html,default.asp 등)의 파일이 존재하지 않을 때 자동으로 디렉터리 리스트를 출력하는 취약점"
        contents = ""
        is_cve = "Safe"
        c=0
        url = "http://"+url
        lst = list(extract_links_from_url(url))
        for i in lst:
            toryurl = url+"/"+lst[int(c)]
            path = get_urldirectorypath(toryurl)
            html = return_souporhtml(path, "html")

            s = regex_search('Index of /', html)

        if s == None:
            contents = "This website is SAFE from Directory listing"
        else:
            contents = path
            is_cve = "Risk"
            c+=1
        return (module_name, description, purpose, security_threat, contents.strip(), is_cve)



    # url_2="210.110.39.89/bWAPP"
    # url_2="210.110.39.89/DVWA"
    # url_2="43.201.100.180"
    url_2="210.110.39.89/testboard"
    url_4="43.201.100.180"



    Total_list=[]



    a="check_cve(get_header('{}'))".format(url)
    b="adpage('{}')".format(url)
    c="check_encryption_support('{}')".format(url)
    d="dicxss('{}')".format(url)
    e="sqltest('{}')".format(url)
    f="dicrec('{}')".format(url)
    func_name=[a,b,c,d,e,f]
    for strfunc in func_name:
        func=eval(strfunc)
        returns = func
        temp_dict = {"vulnerability": 1,"description":1, "purpose": 1, "security_threat": 1, "content": 1, "status": 1}
        temp_dict["vulnerability"]=returns[0]
        temp_dict["description"]=returns[1]
        temp_dict["purpose"]=returns[2]
        temp_dict["security_threat"]=returns[3]
        temp_dict["content"]=returns[4]
        temp_dict["status"]=returns[5]

        Total_list.append(temp_dict)

    return json.dumps(Total_list)

if __name__=="__main__":
    print(return_json_data("43.201.100.180"))
    # print(return_json_data("210.110.39.89/testboard"))
    # print(return_json_data("210.110.39.89/DVWA"))
    # print(return_json_data("43.201.117.55"))