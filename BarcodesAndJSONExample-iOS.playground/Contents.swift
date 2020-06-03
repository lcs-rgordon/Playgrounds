import UIKit
import CommonCrypto
import PlaygroundSupport


/*:
 ## Helper code
 In order to make a request that returns JSON data from the DigitEyes API, a "signature" must be appended to the request URL.
 
 Based on [provided documentation](https://www.digit-eyes.com/specs/UPCAPIImplementation.pdf) the signature is built based upon an HMAC (keyed-hash message authentication code) of the UPC code, using the authentication key provided by Digit Eyes when an account is created with them.
 
 Here is the [source for this code](https://stackoverflow.com/questions/26970807/implementing-hmac-and-sha1-encryption-in-swift
 ).
 */

// Define the different types of HMAC hashing algorithms
// HMAC = "keyed-hash message authentication code
// See: https://en.wikipedia.org/wiki/HMAC
enum HMACAlgorithm {
    case MD5, SHA1, SHA224, SHA256, SHA384, SHA512
    
    func toCCHmacAlgorithm() -> CCHmacAlgorithm {
        var result: Int = 0
        switch self {
        case .MD5:
            result = kCCHmacAlgMD5
        case .SHA1:
            result = kCCHmacAlgSHA1
        case .SHA224:
            result = kCCHmacAlgSHA224
        case .SHA256:
            result = kCCHmacAlgSHA256
        case .SHA384:
            result = kCCHmacAlgSHA384
        case .SHA512:
            result = kCCHmacAlgSHA512
        }
        return CCHmacAlgorithm(result)
    }
    
    func digestLength() -> Int {
        var result: CInt = 0
        switch self {
        case .MD5:
            result = CC_MD5_DIGEST_LENGTH
        case .SHA1:
            result = CC_SHA1_DIGEST_LENGTH
        case .SHA224:
            result = CC_SHA224_DIGEST_LENGTH
        case .SHA256:
            result = CC_SHA256_DIGEST_LENGTH
        case .SHA384:
            result = CC_SHA384_DIGEST_LENGTH
        case .SHA512:
            result = CC_SHA512_DIGEST_LENGTH
        }
        return Int(result)
    }
}

// Extend the String type to allow creations of a base64 encoded HMAC hash
extension String {
    
    func hmac(algorithm: HMACAlgorithm, key: String) -> String {
        
        let cKey = key.cString(using: String.Encoding.utf8)
        
        let cData = self.cString(using: String.Encoding.utf8)
        
        var result = [CUnsignedChar](repeating: 0, count: Int(algorithm.digestLength()))
        
        CCHmac(algorithm.toCCHmacAlgorithm(), cKey!, Int(strlen(cKey!)), cData!, Int(strlen(cData!)), &result)
        
        let hmacData:NSData = NSData(bytes: result, length: (Int(algorithm.digestLength())))
        
        let hmacBase64 = hmacData.base64EncodedString(options: NSData.Base64EncodingOptions.lineLength76Characters)
        
        return String(hmacBase64)
    }
    
}

/*:
 ## Build required signature
 Here we create the required signature based upon a UPC code and our authorization key.
 */

// UPC: 7501035911208
// App key: /wADzn2k+r4k
// Auth key: Be67Q9d5b5Bm4Cr7

// Get the signature string required for using the Digit Eyes API
let exampleSignature: String = "7501035911208".hmac(algorithm: HMACAlgorithm.SHA1, key: "Be67Q9d5b5Bm4Cr7")

/*:
 ## Build request URL
 Here we build the URL that will actually be used to lookup information about a product based on its UPC code. The resulting address can be copy-pasted into a browser address bar to see the results.
 */

// Build a URL to retrieve the JSON response from DigitEyes
func getDataLookupURL(forUPC providedUPC: String) -> URL {
    
    // What we need to build (for example):
    /*
     
     https://www.digit-eyes.com/gtin/v2_0/?upcCode=7501035911208 &field_names=all&language=en&app_key=/wADzn2k+r4k&signature=NaaeIhj5TNzRhjSWzyeNbca969g=
     
     */
    
    // Define the authorization key
    let myAuthKey = "Be67Q9d5b5Bm4Cr7"
    
    // Define the application key
    let myAppKey = "/wADzn2k+r4k"
    
    // Get the signature
    let signature: String = providedUPC.hmac(algorithm: .SHA1, key: myAuthKey)
    
    // Assemble the address
    let address = "https://www.digit-eyes.com/gtin/v2_0/?upcCode=\(providedUPC)&field_names=all&language=en&app_key=\(myAppKey)&signature=\(signature)"
    
    return URL(string: address)!
    
}

// Get the URL for a given UPC code
//print(getDataLookupURL(forUPC: "7501035911208").absoluteString)

// Get the URL for a given UPC code
//print(getDataLookupURL(forUPC: "055742517859").absoluteString)

/*:
 ## Try out getting the data
 Now we use the URL to go out and get the data from the API
 */
let someURL = getDataLookupURL(forUPC: "7501035911208")

//URLSession.shared.dataTask(with: someURL) { data, response, error in
//
//    // If any data was received...
//    if let data = data {
//
//        // ... try to parse it as JSON
//        if let json = try? JSON(data: data) {
//
//            // Try to obtain the image for the product
//            print("\nThe image URL is:")
//            print(json["image"])
//
//            // Try to obtain the description for the product
//            print("\nThe image description is:")
//            print(json["description"])
//
//        }
//
//    }
//}.resume()


/*:
 ## Abstract the data retrieval
 Create a completion handler that attempts to create an instance of the Product type
 */

// Define a structure to represent the scanned product
struct Product {
    var imageAddress: String
    var description: String
}

// Define the completion handler that will be invoked when the data is finished being retrieved from the web service / API
//
// This closure (closure is just a fancy name for "a block of code" will be invoked when the web service has responded
let showProductDetails: (Data?, URLResponse?, Error?) -> Void = {
    
    (data, response, error) in
    
    // We expect the error to be nil
    guard error == nil else {
        
        // If the error is not nil, print the error
        print("Error calling GET with provided URL.")
        print(error!)
        return
        
    }
    
    // We expect data to have been received
    guard let receivedData = data else {
        
        // If no data was received, report this
        print("Error: did not receive any data.")
        return
    }
    
    // Now attempt to parse the data as JSON
    guard let json = try? JSON(data: receivedData) else {
        
        print("Error: Could not convert received data to JSON.")
        return
    }
    
    // Attempt to extract the values we want from the parsed JSON
    guard let image = json["image"].string,
        let description = json["description"].string else {
            
            print("Error: Could not obtain desired data from the Digit Eyes JSON.")
            return
    }
    
    // Create a structure based on the given data
    let retrievedProduct = Product(imageAddress: image, description: description)
    
    print("\nThe image URL is:")
    print(retrievedProduct.imageAddress)
    
    // Try to obtain the description for the product
    print("\nThe image description is:")
    print(retrievedProduct.description)
    
}

// Get the URL for the Digit-Eyes website, based on the provided UPC code
let upcLookupURL = getDataLookupURL(forUPC: "055742517859")

// Now actually set up a task that will invoke the completion handler when complete
let task = URLSession.shared.dataTask(with: upcLookupURL, completionHandler: showProductDetails)

// Now actually carry out the task
// task.resume()

/*:
 ## Embed in a view
 
 Now put it all together, and show the information in a view.
 */


class ExampleViewController : UIViewController {
    
    // MARK: Properties
    let upcField = UITextField()
    let productName = UILabel()
    var productImage = UIImageView()
    let productDetailsButton = UIButton(type: .system)

    // MARK: Methods
    override func viewDidLoad() {
        
        super.viewDidLoad()
        
        // Create a view, set background to white
        let view = UIView()
        view.backgroundColor = .white
        
        // Create a text field and place it top left
        upcField.frame = CGRect(x: 20, y: 20, width: 200, height: 50)
        upcField.placeholder = "Enter UPC code here"
        upcField.text = "055742517859"
        
        // Add the text field to the main view
        view.addSubview(upcField)
        
        // Create a button to retrieve the data
        productDetailsButton.frame = CGRect(x: 17, y: 60, width: 140, height: 50)
        
        // Set text on button
        productDetailsButton.setTitle("Get product details", for: .normal)
        productDetailsButton.setTitle("Pressed + Hold", for: .highlighted)
        
        // Set button action
        productDetailsButton.addTarget(self, action: #selector(getProductDetails(_:)), for: .touchUpInside)
        
        // Position the label
        productName.frame = CGRect(x: 20, y: 100, width: 400, height: 50)
        
        // Add a label to the main view
        view.addSubview(productName)
        
        view.addSubview(productDetailsButton)
        self.view = view
    }
    
    @objc func getProductDetails(_ sender:UIButton!)
    {

        // Disable the button
        productDetailsButton.isEnabled = false
        
        // Define the completion handler that will be invoked to retrieve image data
        let getProductImage: (Data?, URLResponse?, Error?) -> Void = {
            
            (data, response, error) in
            
            // We expect the error to be nil
            guard error == nil else {
                
                // If the error is not nil, print the error
                print("Error calling GET with provided URL.")
                print(error!)
                return
                
            }
            
            // We expect data to have been received
            guard let receivedData = data else {
                
                // If no data was received, report this
                print("Error: did not receive any data.")
                return
            }
            
            // Now attempt to set the UIImage data
            guard let image = UIImage(data: receivedData) else {
                
                // Could not create an image from received data...
                print("Error: Could not create an image from the received data")
                return
            }
            
            // Now place this image in a view so it is visible
            self.productImage = UIImageView(image: image)
            self.productImage.frame = CGRect(origin: CGPoint(x: 20, y: 150), size: image.size)
            
            // Add the image view to the parent view
            self.view.addSubview(self.productImage)
                
        }
        
        // Define the completion handler that will be invoked when the data is finished being retrieved from the web service / API
        //
        // This closure (closure is just a fancy name for "a block of code" will be invoked when the web service has responded
        let getScannedProductDetails: (Data?, URLResponse?, Error?) -> Void = {
            
            (data, response, error) in
            
            // We expect the error to be nil
            guard error == nil else {
                
                // If the error is not nil, print the error
                print("Error calling GET with provided URL.")
                print(error!)
                return
                
            }
            
            // We expect data to have been received
            guard let receivedData = data else {
                
                // If no data was received, report this
                print("Error: did not receive any data.")
                return
            }
            
            // Now attempt to parse the data as JSON
            guard let json = try? JSON(data: receivedData) else {
                
                print("Error: Could not convert received data to JSON.")
                return
            }
            
            // Attempt to extract the values we want from the parsed JSON
            guard let image = json["image"].string,
                let description = json["description"].string else {
                    
                    print("Error: Could not obtain desired data from the Digit Eyes JSON.")
                    return
            }
            
            // Create a structure based on the given data
            let retrievedProduct = Product(imageAddress: image, description: description)
            
            print("\nFrom the view, the image URL is:")
            print(retrievedProduct.imageAddress)
            
            // Try to obtain the description for the product
            print("\nFrom the view, the image description is:")
            print(retrievedProduct.description)
            
            // Set the product name
            self.productName.text = retrievedProduct.description
            
            // Define a URL for the image
            guard let productImageURL = URL(string: retrievedProduct.imageAddress) else {
                
                print("Could not create a URL from image address provided by DigitEyes.")
                return
            }
            
            // Now go get the actual image
            let getProductImageTask = URLSession.shared.dataTask(with: productImageURL, completionHandler: getProductImage)

            // Now actually carry out the task
            getProductImageTask.resume()

            
        }
        
        // Get the URL for the Digit-Eyes website, based on the provided UPC code
        let upcLookupURL = getDataLookupURL(forUPC: self.upcField.text!)

        // Now actually set up a task that will invoke the completion handler when complete
        let getProductDetailsTask = URLSession.shared.dataTask(with: upcLookupURL, completionHandler: getScannedProductDetails)

        // Temporarily set the results label
        self.productName.text = "Working..."
        
        // Now actually carry out the task
        getProductDetailsTask.resume()
        
        print("Button tapped")
    }
    
}

PlaygroundPage.current.liveView = ExampleViewController()

