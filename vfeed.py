import os
import datetime
import sqlite3

path = os.environ["WORKDIR"]

def execute():
    print ("hello the world!")

dbname = path + "/lookup_plugins/vfeed/vfeed.db"

try:
    conn = sqlite3.connect(dbname)
    c = conn.cursor()
except Exception, e:
    print 'Database Error %s' %e

def get_d2(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            params = (cve,)
            results = c.execute('SELECT * FROM map_cve_d2 WHERE cveid=?', params)
            scriptnames = []
            scripturls = []
            for row in results.fetchall():
                try:
                    if not row[0] in scriptnames:
                        scriptnames.append(row[0])
                except:
                    pass
                try:
                    if not row[1] in scripturls:
                        scripturls.append(row[1])
                except:
                    pass
            if len(scriptnames) > 0:
                i['$VFd2ScriptName'] = scriptnames
            if len(scripturls) > 0:
                i['$VFd2ScriptURLs'] = scripturls
    return inward_array

def get_edb(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            params = (cve,)
            results = c.execute('SELECT * FROM map_cve_exploitdb WHERE cveid=?', params)
            ids = []
            scripts = []
            urls = []
            for row in results.fetchall():
                try:
                    if not row[0] in ids:
                        ids.append(row[0])
                except:
                    pass
                try:
                    if not row[1] in scripts:
                        scripts.append(row[1])
                except:
                    pass
                try:
                    url = "http://www.exploit-db.com/exploits/" + row[0]
                    if not url in urls:
                        urls.append(url)
                except:
                    pass
            if len(ids) > 0:
                i['$VFExploitDBIDs'] = ids
            if len(scripts) > 0:
                i['$VFExploitDBScripts'] = scripts
            if len(urls) > 0:
                i['$VFExploitDBURLs'] = scripts
    return inward_array

def get_msf(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            params = (cve,)
            results = c.execute('SELECT * FROM map_cve_msf WHERE cveid=?', params)
            msfIDs = []
            msfFiles = []
            msfNames = []
            for row in results.fetchall():
                try:
                    if not row[0] in msfIDs:
                        msfIDs.append(row[0])
                except:
                    pass
                try:
                    if not row[1] in msfFiles:
                        msfFiles.append(row[1])
                except:
                    pass
                try:
                    if not row[2] in msfNames:
                        msfNames.append(row[2])
                except:
                    pass
            if len(msfIDs) > 0:
                i['$VFMsfIDs'] = msfIDs
            if len(msfFiles) > 0:
                i['$VFMsfScriptFiles'] = msfFiles
            if len(msfNames) > 0:
                i['$VFMsfScriptNames'] = msfNames
    return inward_array

def get_saint(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            params = (cve,)
            results = c.execute('SELECT * FROM map_cve_saint WHERE cveid=?', params)
            exploitIDs = []
            exploitTitles = []
            exploitLinks = []
            for row in results.fetchall():
                try:
                    if not row[0] in exploitIDs:
                        exploitIDs.append(row[0])
                except:
                    pass
                try:
                    if not row[1] in exploitTitles:
                        exploitTitles.append(row[1])
                except:
                    pass
                try:
                    if not row[2] in exploitLinks:
                        exploitLinks.append(row[2])
                except:
                    pass
            if len(exploitIDs) > 0:
                i['$VFSaintExploitID'] = exploitIDs
            if len(exploitTitles) > 0:
                i['$VFSaintExploitTitles'] = exploitTitles
            if len(exploitLinks) > 0:
                i['$VFSaintExploitLinks'] = exploitLinks
    return inward_array

def get_capec(inward_array, var_array):
    dictList = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            params = (cve,)
            cweresults = c.execute('SELECT cweid FROM cve_cwe WHERE cveid=?', params)
            cwerows = c.fetchall()
            if len(cwerows) > 0:
                for cwerow in cwerows:
                    params = (cwerow[0],)
                    results = c.execute('SELECT * FROM cwe_capec WHERE cweid=?', params)
                    capecrows = results.fetchall()
                    if len(capecrows) > 0:
                        for capecrow in capecrows:
                            dicti = {}
                            dicti = dict(i)
                            dicti['$VFCweID'] = cwerow[0]
                            capecid = capecrow[0]
                            subparams = (capecid,)
                            subresults = c.execute('SELECT * FROM capec_db WHERE capecid=?', subparams)
                            capecTitles = []
                            capecAttacks = []
                            capecURLs = []
                            capecMitigations = []
                            for subrow in subresults.fetchall():
                                try:
                                    if not subrow[0] in capecTitles:
                                        capecTitles.append(subrow[0])
                                except:
                                    pass
                                try:
                                    if not subrow[1] in capecAttacks:
                                        capecAttacks.append(subrow[1])
                                except:
                                    pass
                                try:
                                    if not ("https://capec.mitre.org/data/definitions/" + subrow[0] + ".html") in capecURLs:
                                        capecURLs.append(("https://capec.mitre.org/data/definitions/" + subrow[0] + ".html"))
                                except:
                                    pass
                            subresults = c.execute('SELECT * FROM capec_mit WHERE capecid=?', subparams)
                            for subrow in subresults.fetchall():
                                try:
                                    if not subrow[0] in capecMitigations:
                                        capecMitigations.append(subrow[0])
                                except:
                                    pass
                            if len(capecTitles) > 0:
                                dicti['$VFCapecIDs'] = capecTitles
                            if len(capecAttacks) > 0:
                                dicti['$VFCapecTitless'] = capecAttacks
                            if len(capecURLs) > 0:
                                dicti['$VFCapecURLs'] = capecURLs
                            if len(capecMitigations):
                                dicti['$VFCapecMitigations'] = capecMitigations
                            dictList.append(dicti)
                    else:
                        dicti = {}
                        dicti = dict(i)
                        dicti['$VFCweID'] = cwerow[0]
                        dictList.append(dicti)
            else:
                dicti = {}
                dicti = dict(i)
                dictList.append(dicti)
    if dictList:
        return dictList
    else:
        return inward_array

def get_category(inward_array, var_array):
    dictList = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            params = (cve,)
            cweresults = c.execute('SELECT cweid FROM cve_cwe WHERE cveid=?', params)
            cwerows = c.fetchall()
            if len(cwerows) > 0:
                for cwerow in cwerows:
                    params = (cwerow[0],)
                    results = c.execute('SELECT * FROM cwe_category WHERE cweid=?', params)
                    categoryrows = results.fetchall()
                    if len(categoryrows) > 0:
                        for categoryrow in categoryrows:
                            dicti = {}
                            dicti = dict(i)
                            dicti['$VFCweID'] = cwerow[0]
                            fill = 0
                            try:
                                dicti['$VFCategoryID'] = categoryrow[0]
                                fill = 1
                            except:
                                pass
                            try:
                                dicti['$VFCategoryTitle'] = categoryrow[1]
                                fill = 1
                            except:
                                pass
                            try:
                                dicti['$VFCategoryURL'] = "https://cwe.mitre.org/data/definitions/" + str(categoryrow[2]).replace("CWE-", "") + ".html"
                                fill = 1
                            except:
                                pass
                            if fill == 1:
                                dictList.append(dicti)
                    else:
                        dicti = {}
                        dicti = dict(i)
                        dicti['$VFCweID'] = cwerow[0]
                        dictList.append(dicti)
            else:
                dicti = {}
                dicti = dict(i)
                dictList.append(dicti)
    if dictList:
        return dictList
    else:
        return inward_array

def get_cpe(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            params = (cve,)
            results = c.execute('SELECT * FROM cve_cpe WHERE cveid=?', params)
            for row in results.fetchall():
                try:
                    i['$VFCPE'] = row[0]
                except:
                    pass
    return inward_array

def get_cve(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            params = (cve,)
            results = c.execute('SELECT * FROM nvd_db WHERE cveid=?', params)
            for row in results.fetchall():
                try:
                    i['$VFCVEDatePublished'] = row[1]
                except:
                    pass
                try:
                    i['$VFCVEDateModified'] = row[2]
                except:
                    pass
                try:
                    i['$VFCVESummary'] = row[3]
                except:
                    pass
    return inward_array

def get_cwe(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            params = (cve,)
            cweresults = c.execute('SELECT cweid FROM cve_cwe WHERE cveid=?', params)
            cweList = []
            for cwerow in cweresults.fetchall():
                try:
                    if not cwerow[0] in cweList:
                        cweList.append(cwerow[0])
                except:
                    pass
            if len(cweList) > 0:
                i['$VFCweIDs'] = cweList
    return inward_array

def get_wasc(inward_array, var_array):
    dictList = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            params = (cve,)
            cweresults = c.execute('SELECT cweid FROM cve_cwe WHERE cveid=?', params)
            cwerows = cweresults.fetchall()
            if len(cwerows) > 0:
                for cwerow in cwerows:
                    params = (cwerow[0],)
                    results = c.execute('SELECT * FROM cwe_wasc WHERE cweid=?', params)
                    wascrows = results.fetchall()
                    if len(wascrows) > 0:
                        for wascrow in wascrows:
                            dicti = {}
                            dicti = dict(i)
                            dicti['$VFCweID'] = cwerow[0]
                            fill = 0
                            try:
                                dicti['$VFWascID'] = wascrow[1]
                                fill = 1
                            except:
                                pass
                            try:
                                dicti['$VFWascTitle'] = wascrow[1]
                                fill = 1
                            except:
                                pass
                            try:
                                dicti['$VFWascURL'] = "http://projects.webappsec.org/" + str(wascrow[1]).replace(" ", "-") + ".html"
                                fill = 1
                            except:
                                pass
                            if fill == 1:
                                dictList.append(dicti)
                    else:
                        dicti = {}
                        dicti = dict(i)
                        dicti['$VFCweID'] = cwerow[0]
                        dictList.append(dicti)
            else:
                dicti = {}
                dicti = dict(i)
                dictList.append(dicti)
    if dictList:
        return dictList
    else:
        return inward_array

def get_aixapar(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            params = (cve,)
            results = c.execute('SELECT * FROM map_cve_aixapar WHERE cveid=?', params)
            ids = []
            urls = []
            for row in results.fetchall():
                try:
                    if not row[0] in ids:
                        ids.append(row[0])
                except:
                    pass
                try:
                    url = "http://www-01.ibm.com/support/docview.wss?uid=swg1" + str(row[0])
                    if not url in urls:
                        urls.append(url)
                except:
                    pass
            if len(ids) > 0:
                i['$VFAixaparIDs'] = ids
            if len(urls) > 0:
                i['$VFAixaparURLs'] = urls
    return inward_array

def get_cisco(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            params = (cve,)
            results = c.execute('SELECT * FROM map_cve_cisco WHERE cveid=?', params)
            ids = []
            for row in results.fetchall():
                try:
                    if not row[0] in ids:
                        ids.append(row[0])
                except:
                    pass
            if len(ids) > 0:
                i['$VFCiscoIDs'] = ids
    return inward_array

def get_debian(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            params = (cve,)
            results = c.execute('SELECT * FROM map_cve_debian WHERE cveid=?', params)
            ids = []
            urls = []
            for row in results.fetchall():
                try:
                    if not row[0] in ids:
                        ids.append(row[0])
                except:
                    pass
                try:
                    url = "https://security-tracker.debian.org/tracker/" + str(row[0])
                    if not url in urls:
                        urls.append(url)
                except:
                    pass
            if len(ids) > 0:
                i['$VFDebianIDs'] = ids
            if len(urls) > 0:
                i['$VFDebianURLs'] = urls

    return inward_array

def get_fedora(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            params = (cve,)
            results = c.execute('SELECT * FROM map_cve_fedora WHERE cveid=?', params)
            ids = []
            urls = []
            for row in results.fetchall():
                try:
                    if not row[0] in ids:
                        ids.append(row[0])
                except:
                    pass
                try:
                    url = "https://admin.fedoraproject.org/updates/" + str(row[0])
                    if not url in urls:
                        urls.append(url)
                except:
                    pass
            if len(ids) > 0:
                i['$VFFedoraIDs'] = ids
            if len(urls) > 0:
                i['$VFFedoraURLs'] = urls

    return inward_array

def get_gentoo(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            params = (cve,)
            results = c.execute('SELECT * FROM map_cve_gentoo WHERE cveid=?', params)
            ids = []
            urls = []
            for row in results.fetchall():
                try:
                    if not row[0] in ids:
                        ids.append(row[0])
                except:
                    pass
                try:
                    url = "https://security.gentoo.org/glsa/" + str(row[0]).replace('GLSA-', '')
                    if not url in urls:
                        urls.append(url)
                except:
                    pass
            if len(ids) > 0:
                i['$VFGentooIDs'] = ids
            if len(urls) > 0:
                i['$VFGentooURLs'] = urls

    return inward_array

def get_hp(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            params = (cve,)
            results = c.execute('SELECT * FROM map_cve_hp WHERE cveid=?', params)
            ids = []
            urls = []
            for row in results.fetchall():
                try:
                    if not row[0] in ids:
                        ids.append(row[0])
                except:
                    pass
                try:
                    if not row[1] in urls:
                        urls.append(row[1])
                except:
                    pass
            if len(ids) > 0:
                i['$VFHpIDs'] = ids
            if len(urls) > 0:
                i['$VFHpURLs'] = urls

    return inward_array

def get_mandriva(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            params = (cve,)
            results = c.execute('SELECT * FROM map_cve_mandriva WHERE cveid=?', params)
            ids = []
            urls = []
            for row in results.fetchall():
                try:
                    if not row[0] in ids:
                        ids.append(row[0])
                except:
                    pass
                try:
                    url = "http://www.mandriva.com/security/advisories?name=" + str(row[0])
                    if not url in urls:
                        urls.append(url)
                except:
                    pass
            if len(ids) > 0:
                i['$VFMandrivaIDs'] = ids
            if len(urls) > 0:
                i['$VFMandrivaURLs'] = urls

    return inward_array

def get_microsoft(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            params = (cve,)
            results = c.execute('SELECT * FROM map_cve_ms WHERE cveid=?', params)
            ids = []
            kbs = []
            titles = []
            urls = []
            for row in results.fetchall():
                try:
                    if not row[0] in ids:
                        ids.append(row[0])
                except:
                    pass
                try:
                    if not row[1] in kbs:
                        kbs.append(row[1])
                except:
                    pass
                try:
                    if not row[2] in titles:
                        titles.append(row[2])
                except:
                    pass
                try:
                    if not row[3] in url:
                        urls.append(row[3])
                except:
                    pass
            if len(ids) > 0:
                i['$VFMicrosoftIDs'] = ids
            if len(kbs) > 0:
                i['$VFMicrosoftKBs'] = kbs
            if len(titles) > 0:
                i['$VFMicrosoftTitless'] = titles
            if len(urls) > 0:
                i['$VFMicrosoftURLs'] = urls

    return inward_array

def get_redhat(inward_array, var_array):
    lis = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cve_redhat WHERE cveid=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    item = {}
                    item = dict(i)
                    item.update({"$VFRedhatId": str(data[0]),
                            "$VFRedhatCategory": "Redhat", '$VFRedhatCVE': cve,
                            "$VFRedhatUrl": "https://rhn.redhat.com/errata/" + str.replace(str(data[0]), ':', '-') + ".html"})
                    if data[1] != '':
                        item['$VFRedhatOvalID'] = str(data[1])
                    if data[2] != '':
                        item['$VFRedhatTitle'] = str(data[2])
                    lis.append(item)
                    query2 = (str(data[0]),)
                    c.execute('SELECT * FROM map_redhat_bugzilla WHERE redhatid=?', query2)
                    for data2 in c.fetchall():
                        item2 = {"$VFRedhatId": str(data2[1]), "$VFRedhatDate": str(data2[0]),
                                 "$VFRedhatTitle": str(data2[2]), "$VFRedhatAssociated_redhat": str(data[0]),
                                 "$VFRedhatCategory": "Bugzilla", "$CVE": cve,
                                 "$VFRedhatUrl": "https://bugzilla.redhat.com/show_bug.cgi?id=" + str(data2[1])}
                        lis.append(item2)
            else:
                item = {}
                item = dict(i)
                lis.append(item)
    if lis:
        return lis
    else:
        return inward_array

def get_suse(inward_array, var_array):
    lis = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cve_suse WHERE cveid=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    item = {}
                    item = dict(i)
                    item.update({"$CVE": cve,"$VFSuseId": data[0], "$VFSuseUrl": "https://www.suse.com/security/cve/" + cve + ".html"})
                    lis.append(item)
            else:
                item = {}
                item = dict(i)
                lis.append(item)
    if lis:
        return lis
    else:
        return inward_array

def get_ubuntu(inward_array, var_array):
    lis = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cve_ubuntu WHERE cveid=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    item = {}
                    item = dict(i)
                    item.update({"$CVE": cve,"$VFUbuntuId": data[0], "$VFUbuntuUrl": "http://www.ubuntu.com/usn/" + str(data[0])})
                    lis.append(item)
            else:
                item = {}
                item = dict(i)
                lis.append(item)
    if lis:
        return lis
    else:
        return inward_array

def get_vmware(inward_array, var_array):
    lis = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cve_vmware WHERE cveid=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    item = {}
                    item = dict(i)
                    item.update({"$VFVMwareId": str(data[0]), "$CVE": cve,
                            "$VFVMwareUrl": "https://www.vmware.com/security/advisories/" + str(data[0]) + '.html'})
                    lis.append(item)
            else:
                item = {}
                item = dict(i)
                lis.append(item)
    if lis:
        return lis
    else:
        return inward_array

def get_bid(inward_array, var_array):
    lis = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cve_bid WHERE cveid=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    item = {}
                    item = dict(i)
                    item.update({"$CVE": cve,"$VFBidId": data[0], "$VFBidUrl": "http://www.securityfocus.com/bid/" + str(data[0])})
                    lis.append(item)
            else:
                item = {}
                item = dict(i)
                lis.append(item)
    if lis:
        return lis
    else:
        return inward_array

def get_certvn(inward_array, var_array):
    lis = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cve_certvn WHERE cveid=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    item = {}
                    item = dict(i)
                    item.update({"$CVE": cve, "$VFCertVNId": data[0], "$VFCertVNUrl": data[1]})
                    lis.append(item)
            else:
                item = {}
                item = dict(i)
                lis.append(item)
    if lis:
        return lis
    else:
        return inward_array

def get_iavm(inward_array, var_array):
    lis = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cve_iavm WHERE cveid=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    item = {}
                    item = dict(i)
                    item.update({"$CVE": cve, "$VFIAVMId": data[0], "$VFIAVMKey": data[1], "$VFIAVMTitle": data[2]})
                    lis.append(item)
            else:
                item = {}
                item = dict(i)
                lis.append(item)
    if lis:
        return lis
    else:
        return inward_array

def get_osvdb(inward_array, var_array):
    lis = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cve_osvdb WHERE cveid=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    item = {}
                    item = dict(i)
                    item.update({"$CVE": cve,"$VFOSVDBId": data[0], "$VFOSVDBUrl": "http://www.osvdb.org/" + str(data[0])})
                    lis.append(item)
            else:
                item = {}
                item = dict(i)
                lis.append(item)
    if lis:
        return lis
    else:
        return inward_array

def get_refs(inward_array, var_array):
    lis = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM cve_reference WHERE cveid=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    item = {}
                    item = dict(i)
                    item.update({"$CVE": cve, "$VFRefsVendor": data[0], "$VFRefsUrl": data[1]})
                    lis.append(item)
            else:
                item = {}
                item = dict(i)
                lis.append(item)
    if lis:
        return lis
    else:
        return inward_array

def get_scip(inward_array, var_array):
    lis = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cve_scip WHERE cveid=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    item = {}
                    item = dict(i)
                    item.update({"$CVE": cve, "$VFSCIPVendor": data[0], "$VFSCIPUrl": data[1]})
                    lis.append(item)
            else:
                item = {}
                item = dict(i)
                lis.append(item)
    if lis:
        return lis
    else:
        return inward_array

def get_cvss(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM nvd_db WHERE cveid=? LIMIT 1', (cve,))
            try:
                data = c.fetchone()
                if len(data) > 0:
                    i["$VFCVSSBase"] = str(data[4])
                    i["$VFCVSSImpact"] = str(data[5])
                    i["$VFCVSSExploitability"] = str(data[6])
                    i["$VFCVSSAccessVector"] = str(data[7])
                    i["$VFCVSSAccessComplexity"] = str(data[8])
                    i["$VFCVSSAuthentication"] = str(data[9])
                    i["$VFCVSSConfidentiality"] = str(data[10])
                    i["$VFCVSSIntegrity"] = str(data[11])
                    i["$VFCVSSAvailability"] = str(data[12])
                    i["$VFCVSSVector"] = str(data[13])
            except:
                pass
    return inward_array

def get_severity(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            try:
                cvss = get_cvss(inward_array, var_array)
                cvss_data = cvss
                top_alert = top_alert_check(inward_array, var_array)
                top_vulnerable = False

                if cvss_data[0]["$VFCVSSBase"] == "not_defined":
                    level = "notDefined"
                    top_vulnerable = "notDefined"
                elif cvss_data[0]["$VFCVSSBase"] == "10.0" and cvss_data[0]["$VFCVSSExploitability"] == "10.0" and cvss_data[0][
                    "$VFCVSSImpact"] == "10.0":
                    level = "high"
                    top_vulnerable = True
                elif cvss_data[0]["$VFCVSSBase"] >= "7.0":
                    level = "high"
                elif "4.0" <= cvss_data[0]["$VFCVSSBase"] <= "6.9":
                    level = "moderate"
                elif "0.1" <= cvss_data[0]["$VFCVSSBase"] <= "3.9":
                    level = "low"

                i["$VFSeverity"] = level
                i["$VFTopVulnerable"] = top_vulnerable
                i["$VFTopAlert"] = top_alert
            except:
                pass
    return inward_array

def top_alert_check(inward_array, var_array):
    top_alert = []
    category = get_category(inward_array, var_array)

    top_category = ['CWE-929', 'CWE-930', 'CWE-931', 'CWE-932', 'CWE-933', 'CWE-934', 'CWE-935', 'CWE-936',
                    'CWE-937', 'CWE-938', 'CWE-810', 'CWE-811', 'CWE-812', 'CWE-813', 'CWE-814', 'CWE-815',
                    'CWE-816', 'CWE-817', 'CWE-818', 'CWE-819', 'CWE-864', 'CWE-865', 'CWE-691']

    for cat in top_category:
        for item in category:
            if item.get("$VFCategoryID") == cat:
                item = {}
                item = dict(i)
                item.update({"$VFAlertID": item.get("$VFCategoryID"), "$VFAlertTitle": item.get("$VFCategoryTitle")})
                top_alert.append(item)

    if top_alert:
        return top_alert
    else:
        return False

def get_snort(inward_array, var_array):
    lis = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cve_snort WHERE cveid=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    item = {}
                    item = dict(i)
                    item.update({"$CVE": cve, "$VFSnortID": str(data[0]), '$VFSnortSignature': str(data[1]), '$VFSnortCategory': str(data[2])})
                    lis.append(item)
            else:
                item = {}
                item = dict(i)
                lis.append(item)
    if lis:
        return lis
    else:
        return inward_array

def get_suricata(inward_array, var_array):
    lis = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cve_suricata WHERE cveid=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    item = {}
                    item = dict(i)
                    item.update({"$CVE": cve, "$VFSurricataID": str(data[0]), '$VFSuricataSignature': str(data[1]), '$VFSuricataClasstype': str(data[2])})
                    lis.append(item)
            else:
                item = {}
                item = dict(i)
                lis.append(item)
    if lis:
        return lis
    else:
        return inward_array

def get_nessus(inward_array, var_array):
    lis = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cve_nessus WHERE cveid=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    item = {}
                    item = dict(i)
                    item.update({"$CVE": cve, "$VFNessusID": str(data[0]), "$VFNessusFile": str(data[1]), "$VFNessusName": str(data[2]),
                            "$VFNessusFamily": str(data[3])})
                    lis.append(item)
            else:
                item = {}
                item = dict(i)
                lis.append(item)
    if lis:
        return lis
    else:
        return inward_array

def get_nmap(inward_array, var_array):
    lis = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cve_nmap WHERE cveid=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    item = {}
                    item = dict(i)
                    item.update({"$CVE": cve, "$VFNmapFile": str(data[0]), "$VFNmapFamily": str(data[1]).replace('"', '').strip(),
                            "$VFNmapUrl": "https://nmap.org/nsedoc/scripts/" + str(data[0]).replace(".nse", ".html")})
                    lis.append(item)
            else:
                item = {}
                item = dict(i)
                lis.append(item)
    if lis:
        return lis
    else:
        return inward_array

def get_openvas(inward_array, var_array):
    lis = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cve_openvas WHERE cveid=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    item = {}
                    item = dict(i)
                    item.update({"$CVE": cve, "$VFOpenVASID": str(data[0]), "$VFOpenVASFile": str(data[1]), "$VFOpenVASName": str(data[2]),
                            "$VFOpenVASFamily": str(data[3])})
                    lis.append(item)
            else:
                item = {}
                item = dict(i)
                lis.append(item)
    if lis:
        return lis
    else:
        return inward_array

def get_oval(inward_array, var_array):
    lis = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cve_oval WHERE cveid=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    item = {}
                    item = dict(i)
                    title = data[2]
                    if not isinstance(title, str):
                        title = title.encode('ascii', 'ignore')
                    item.update({"$VFOvalID": data[0], "$VFOvalClass": data[1], "$VFOvalTitle": title, "$VFOvalURL": "https://oval.cisecurity.org/repository/search/definition/" + data[0]})
                    lis.append(item)
            else:
                item = {}
                item = dict(i)
                lis.append(item)
    if lis:
        return lis
    else:
        return inward_array

def search_for_cve(inward_array, var_array):
    dictList = []
    for i in inward_array:
        if var_array[0] in i:
            summary = i[var_array[0]]
            params = ("%" + summary + "%",)
            results = c.execute('SELECT * FROM nvd_db WHERE summary LIKE ?', params)
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    dicti = {}
                    dicti = dict(i)
                    try:
                        dicti['$CVE'] = data[0]
                    except:
                        pass
                    try:
                        dicti['$CVESummary'] = data[3]
                    except:
                        pass
                    dictList.append(dicti)
            else:
                dicti = {}
                dicti = dict(i)
                dictList.append(dicti)

    if dictList:
        return dictList
    else:
        return inward_array

def sid_to_cve(inward_array, var_array):
    lis = []
    for i in inward_array:
        if var_array[0] in i:
            sid = 'sid:' + str(i[var_array[0]])
            c.execute('SELECT cveid FROM map_cve_snort WHERE snort_id=?', (sid, ))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    item = {}
                    item = dict(i)
                    item.update({'$CVE': data[0]})
                    lis.append(item)
            else:
                item = {}
                item = dict(i)
                lis.append(item)
    if lis:
        return lis
    else:
        return inward_array

def cve_to_exploitdb(inward_array, var_array):
    lis = []
    for i in inward_array:
        if var_array:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT exploitdbid FROM map_cve_exploitdb WHERE cveid=?', (cve, ))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    item = {}
                    item = dict(i)
                    item.update({'$ExploitDBID': data[0]})
                    lis.append(item)
            else:
                item = {}
                item = dict(i)
                lis.append(item)
    if lis:
        return lis
    else:
        return inward_array

def validate_cve(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            orig_cve = i[var_array[0]]
            cve = i[var_array[0]].upper()
            if (orig_cve[0:3]).upper() != "CVE":
                cve  = "CVE-" + orig_cve
            if not 'CVE-' in cve:
                cve = cve.replace('CVE', 'CVE-')
            if not '-' in cve[4:]:
                cve = cve[0:8] + "-" + cve[8:]
            id = cve[9:]
            if len(id) <= 3:
                zerosToAdd = 4 - len(id)
                zeros = ""
                m = 0
                while(m < zerosToAdd):
                    zeros = zeros + "0"
                    m = m + 1
                cve = cve[0:9] + zeros + str(id)
            i[var_array[0]] = cve
    return inward_array
