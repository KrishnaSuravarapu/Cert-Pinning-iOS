//
//  ViewController.swift
//  Cert Pinning
//
//  Created by Krishna Suravarapu on 27/01/22.
//

import UIKit
import WebKit

class ViewController: UIViewController, UISearchBarDelegate, WKNavigationDelegate {
    @IBOutlet weak var webView: WKWebView!
    
    @IBOutlet weak var progressBar: UIProgressView!
    
    @IBOutlet weak var searchBar: UISearchBar!
    
    @IBOutlet weak var toggleCertPinning: UIBarButtonItem!
    
    @IBOutlet weak var certText: UITextField!
    
    @IBOutlet weak var switchCertPinning: UISwitch!
    
    @IBAction func deleteData(_ sender: Any) {
        clean()
    }
    
    var bundledSslCert = "google"
    
    var bundledSslCertExt = "der"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        // call the 'keyboardWillShow' function when the view controller receive the notification that a keyboard is going to be shown
        NotificationCenter.default.addObserver(self, selector: #selector(ViewController.keyboardWillShow), name: UIResponder.keyboardWillShowNotification, object: nil)
        // call the 'keyboardWillHide' function when the view controlelr receive notification that keyboard is going to be hidden
        NotificationCenter.default.addObserver(self, selector: #selector(ViewController.keyboardWillHide), name: UIResponder.keyboardWillHideNotification, object: nil)
        
        let url = URL(string: "https://www.google.com")
        let request = URLRequest(url: url!, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData)
        webView.load(request)
        webView.addSubview(progressBar)
        webView.addObserver(self, forKeyPath: #keyPath(WKWebView.estimatedProgress), options: .new, context: nil)
        webView.navigationDelegate = self
    }

    override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey : Any]?, context: UnsafeMutableRawPointer?) {
        if keyPath == "estimatedProgress" {
            progressBar.progress = Float(webView.estimatedProgress)
        }
    }
    
    func searchBarSearchButtonClicked(_ searchBar: UISearchBar) {
        searchBar.resignFirstResponder()
        let url = URL(string: "https://\(searchBar.text!)")
        let request = URLRequest(url: url!, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData)
        webView.load(request)
    }
    
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        progressBar.progress = 0.0
    }
    
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        progressBar.progress = 0.0
    }
    
    func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        NSLog("didReceive challenge")
        
        let whiteStaticList = ["i.ytimg.com", "yt3.ggpht.com", "googleads.g.doubleclick.net", "fonts.gstatic.com", "static.doubleclick.net", "fbcdn.net", "fbsbx.com", "github.githubassets.com", "avatars.githubusercontent.com", "api.github.com", "collector.githubapp.com", "play.google.com", "accounts.google.com"]
        let whiteList = whiteStaticList.filter { challenge.protectionSpace.host.hasPrefix($0) }
        
        if whiteList.count > 0 || !switchCertPinning.isOn {
            if !switchCertPinning.isOn {
                NSLog("ignoring SSL Pinning")
            }
            else {
                NSLog("whitelisting \(challenge.protectionSpace.host)")
            }
            completionHandler(URLSession.AuthChallengeDisposition.useCredential, URLCredential(trust:challenge.protectionSpace.serverTrust!))
            return
        }
        
        if (challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust) {
            guard let serverTrust = challenge.protectionSpace.serverTrust else { return completionHandler(.useCredential, nil) }
            var secresult = SecTrustResultType.invalid
            let status = SecTrustEvaluate(serverTrust, &secresult)
            if(errSecSuccess == status) {
                if let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) {
                    let serverCertificateData = SecCertificateCopyData(serverCertificate)
                    let data = CFDataGetBytePtr(serverCertificateData);
                    let size = CFDataGetLength(serverCertificateData);
                    if certText.text != "" {
                        bundledSslCert = certText.text!
                    }
                    let cert1 = NSData(bytes: data, length: size)
                    let file_der = Bundle.main.path(forResource: bundledSslCert, ofType: bundledSslCertExt)

                    if let file = file_der {
                        if let cert2 = NSData(contentsOfFile: file) {
                            if cert1.isEqual(to: cert2 as Data) && challenge.previousFailureCount == 0{
                                NSLog("validation successful for \(challenge.protectionSpace.host)")
                                completionHandler(URLSession.AuthChallengeDisposition.useCredential, URLCredential(trust:serverTrust))
                                return
                            }
                            else{
                                NSLog("validation failed for \(challenge.protectionSpace.host)")
                            }
                        }
                    }
                }
            }
        }
        // Certificate validation / Pinning failed
        completionHandler(URLSession.AuthChallengeDisposition.cancelAuthenticationChallenge, nil)
        alertHandler(progressBar: progressBar)
    }
    
    @objc func keyboardWillShow(notification: NSNotification) {
            
        guard let keyboardSize = (notification.userInfo?[UIResponder.keyboardFrameEndUserInfoKey] as? NSValue)?.cgRectValue else {
           // if keyboard size is not available for some reason, dont do anything
           return
        }
      
      // move the root view up by the distance of keyboard height
      self.view.frame.origin.y = 0 - keyboardSize.height
    }

    @objc func keyboardWillHide(notification: NSNotification) {
      // move back the root view origin to zero
      self.view.frame.origin.y = 0
    }
    
    func alertHandler(progressBar: UIProgressView){
        let errorAlert = UIAlertController(title: "SSL pinning error", message: "Cert Match Failed", preferredStyle: UIAlertController.Style.alert)

        errorAlert.addAction(UIAlertAction(title: "Ok", style: .default, handler: { (action: UIAlertAction!) in
            NSLog("Certificate Validation Failed")
            progressBar.progress = 0.0
        }))

        present(errorAlert, animated: true, completion: nil)
    }
    
    func clean() {
        HTTPCookieStorage.shared.removeCookies(since: Date.distantPast)
        NSLog("[WebCacheCleaner] All cookies deleted")
            
        WKWebsiteDataStore.default().fetchDataRecords(ofTypes: WKWebsiteDataStore.allWebsiteDataTypes()) { records in
            records.forEach { record in
                WKWebsiteDataStore.default().removeData(ofTypes: record.dataTypes, for: [record], completionHandler: {})
                NSLog("[WebCacheCleaner] Record \(record) deleted")
            }
        }
    }
}
