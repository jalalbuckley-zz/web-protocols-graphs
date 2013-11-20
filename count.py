#!/usr/bin/env python
# encoding: utf-8

import matplotlib.pyplot as plt
import sys
from time import gmtime, strftime
import os

def main():
    data = open(sys.argv[1], 'r').read()
    noSupportTLSv1_2 = 0.0
    numTargets = 0.0
    protocols = []
    
    directoryName = 'graphs,' + strftime("%Y-%m-%d,%H:%M:%S", gmtime())
    os.mkdir(directoryName)
    protocolsFile = open(directoryName + '/protocols.csv', 'w')
    
    targetHost = data.find('<target host="')
    nextTarget = data.find('<target host="', targetHost+1)
    
    while targetHost != -1:
        numTargets += 1.0
        tlsStart = data.find('<tlsv1_2 title="TLSV1_2 Cipher Suites">', targetHost)
        tlsEnd = data.find('</tlsv1_2>', tlsStart)
        noAccepted = data.find('<acceptedCipherSuites/>', tlsStart)
        if noAccepted < tlsEnd and noAccepted != -1:
            noSupportTLSv1_2 += 1.0
        targetHost = nextTarget
        nextTarget = data.find('<target host="', targetHost+1)
    protocols.append(['TLS v1.2', str( 100*((numTargets - noSupportTLSv1_2)/numTargets) ), str(100*(noSupportTLSv1_2/numTargets))])


    targetHost = data.find('<target host="')
    nextTarget = data.find('<target host="', targetHost+1)
    noSupportTLSv1_1 = 0.0
    while targetHost != -1:
        tlsStart = data.find('<tlsv1_1 title="TLSV1_1 Cipher Suites">', targetHost)
        tlsEnd = data.find('</tlsv1_1>', tlsStart)
        noAccepted = data.find('<acceptedCipherSuites/>', tlsStart)
        if noAccepted < tlsEnd and noAccepted != -1:
            noSupportTLSv1_1 += 1.0
        targetHost = nextTarget
        nextTarget = data.find('<target host="', targetHost+1)
    
    protocols.append(['TLS v1.1', str( 100*((numTargets - noSupportTLSv1_1)/numTargets) ), str(100*(noSupportTLSv1_1/numTargets))])

    targetHost = data.find('<target host="')
    nextTarget = data.find('<target host="', targetHost+1)
    noSupportSSLv2 = 0.0
    while targetHost != -1:
        tlsStart = data.find('<sslv2 title="SSLV2 Cipher Suites">', targetHost)
        tlsEnd = data.find('</sslv2>', tlsStart)
        noAccepted = data.find('<acceptedCipherSuites/>', tlsStart)
        if noAccepted < tlsEnd and noAccepted != -1:
            noSupportSSLv2 += 1.0
        targetHost = nextTarget
        nextTarget = data.find('<target host="', targetHost+1)
    
    protocols.append(['SSL v2', str( 100*((numTargets - noSupportSSLv2)/numTargets) ), str(100*(noSupportSSLv2/numTargets))])

    targetHost = data.find('<target host="')
    nextTarget = data.find('<target host="', targetHost+1)
    noSupportSSLv3 = 0.0
    while targetHost != -1:
        tlsStart = data.find('<sslv3 title="SSLV3 Cipher Suites">', targetHost)
        tlsEnd = data.find('</sslv3>', tlsStart)
        noAccepted = data.find('<acceptedCipherSuites/>', tlsStart)
        if noAccepted < tlsEnd and noAccepted != -1:
            noSupportSSLv3 += 1.0
        targetHost = nextTarget
        nextTarget = data.find('<target host="', targetHost+1)
    
    protocols.append(['SSL v3', str( 100*((numTargets - noSupportSSLv3)/numTargets) ), str(100*(noSupportSSLv3/numTargets))])

    targetHost = data.find('<target host="')
    nextTarget = data.find('<target host="', targetHost+1)
    startPos = data.find('<acceptedCipherSuites>', targetHost+1)
    endPos = data.find('</acceptedCipherSuites>', startPos+1)
    tempCiphers = {}
    ciphers = {}
    cipherStart = data.find('name="', startPos+1)
    cipherEnd = 0
    numCiphers = 0

    while targetHost != -1:
        numCiphers += 1.0
        
        while startPos != -1 and startPos < nextTarget:
            while cipherStart != -1 and cipherStart < endPos:
                if cipherStart != -1 and cipherStart < endPos:
                    cipherEnd = data.find('"/>', cipherStart+1)
                    cipher = data[cipherStart+6:cipherEnd]
                    if cipher not in tempCiphers:
                        tempCiphers[cipher] = 1.0
                cipherStart = data.find('name="', cipherStart+1)
            startPos = data.find('<acceptedCipherSuites>', startPos+1)
            endPos = data.find('</acceptedCipherSuites>', startPos+1)
            cipherStart = data.find('name="', startPos+1)

        if nextTarget == -1:
            while startPos != -1:
                while cipherStart != -1 and cipherStart < endPos:
                    if cipherStart != -1 and cipherStart < endPos:
                        cipherEnd = data.find('"/>', cipherStart+1)
                        cipher = data[cipherStart+6:cipherEnd]
                        if cipher not in tempCiphers:
                            tempCiphers[cipher] = 1.0
                    cipherStart = data.find('name="', cipherStart+1)
                startPos = data.find('<acceptedCipherSuites>', startPos+1)
                endPos = data.find('</acceptedCipherSuites>', startPos+1)
                cipherStart = data.find('name="', startPos+1)

        for c in tempCiphers:
            if c not in ciphers:
                ciphers[c] = tempCiphers[c]
            else:
                pastVal = ciphers[c]
                pastVal += tempCiphers[c]
                ciphers[c] = pastVal
                    
        domainProtocols = []
        
        #Get the Protocols
        tlsStart = data.find('<sslv3 title="SSLV3 Cipher Suites">', targetHost)
        tlsEnd = data.find('</sslv3>', tlsStart)
        noAccepted = data.find('<acceptedCipherSuites/>', tlsStart)
        if noAccepted > tlsEnd and noAccepted != -1:
            domainProtocols.append('SSLv3')
                    
        tlsStart = data.find('<sslv2 title="SSLV2 Cipher Suites">', targetHost)
        tlsEnd = data.find('</sslv2>', tlsStart)
        noAccepted = data.find('<acceptedCipherSuites/>', tlsStart)
        if noAccepted > tlsEnd and noAccepted != -1:
            domainProtocols.append('SSLv2')

        tlsStart = data.find('<tlsv1_2 title="TLSV1_2 Cipher Suites">', targetHost)
        tlsEnd = data.find('</tlsv1_2>', tlsStart)
        noAccepted = data.find('<acceptedCipherSuites/>', tlsStart)
        if noAccepted > tlsEnd and noAccepted != -1:
            domainProtocols.append('TLSv1_2')
                    
        tlsStart = data.find('<tlsv1_1 title="TLSV1_1 Cipher Suites">', targetHost)
        tlsEnd = data.find('</tlsv1_1>', tlsStart)
        noAccepted = data.find('<acceptedCipherSuites/>', tlsStart)
        if noAccepted > tlsEnd and noAccepted != -1:
            domainProtocols.append('TLSv1_1')
    
        #Write to protocols.csv
        targetHostEnd = data.find('"', targetHost+14)
        targetName = data[targetHost+14:targetHostEnd]
        list = targetName + ','
        for key in tempCiphers:
            list += key + ';'
        list += ','

        for protocol in domainProtocols:
            list += protocol + ';'
        list += ','

        list = list[:-1] + '\n'
        protocolsFile.write(list)

        tempCiphers = {}
        targetHost = nextTarget
        nextTarget = data.find('<target host="', targetHost+1)
    
    results = []
    for cipher in ciphers:
        results.append([cipher, str( 100*(ciphers[cipher] / numCiphers) ), str(100 - (100*(ciphers[cipher] / numCiphers)))])

    #Make graphs
    labels = 'Supported', 'Not Supported'
    for sets in [results, protocols]:
        for set in sets:
            title = set[:1][0]
            sizes = set[1:]
            plt.pie(sizes, labels=labels, autopct='%1.1f%%', shadow=True)
            plt.title(title, fontsize=22)
            plt.savefig(directoryName + '/' + title + '.jpg')
            plt.clf()

if __name__ == '__main__':
    main()