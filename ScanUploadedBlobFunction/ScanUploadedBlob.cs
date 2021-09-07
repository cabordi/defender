using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using System.IO;
using System;

namespace ScanUploadedBlobFunction
{
    public static class ScanUploadedBlob
    {
        
        [FunctionName("ScanUploadedBlob")]
        public static void Run([BlobTrigger("%targetContainerName%/{name}", Connection = "windefenderstorage")] Stream myBlob, string name, ILogger log)
        {
            log.LogInformation($"C# Blob trigger ScanUploadedBlob function Processed blob Name:{name} Size: {myBlob.Length} Bytes");
            
            var scannerHost = Environment.GetEnvironmentVariable("windowsdefender_host");
            var scannerPort = Environment.GetEnvironmentVariable("windowsdefender_port");

            var scanner = new ScannerProxy(log, scannerHost);
            var scanResults = scanner.Scan(myBlob, name);
            if (scanResults == null)
            {
                return;
            }
            log.LogInformation($"Scan Results - {scanResults.ToString(", ")}");
            log.LogInformation("Handalng Scan Results");


            // Metadata retrieval
            string blob_path = name;
            string connection_string = "DefaultEndpointsProtocol=https;AccountName=webuildstorageblob;AccountKey=jvgWPM9d++wsfBYyeXko4se/jkk9PHv1wl5bNX5Cr2hjGs1HBWJYZW8XZFeK2U+7N9z9sgxnZ5vfYXxyj1j8pw==;EndpointSuffix=core.windows.net";
            string containerName = Environment.GetEnvironmentVariable("targetContainerName");
            
            BlobServiceClient blobServiceClient = new BlobServiceClient(connection_string);
            BlobContainerClient containerClient = blobServiceClient.GetBlobContainerClient(containerName);

            BlobClient blobClient = containerClient.GetBlobClient(blob_path);
            var blobUri = blobClient.Uri;
            BlobProperties properties = blobClient.GetProperties();
            
            string to_be_scanned = "";
            if (properties.Metadata.ContainsKey("Tobescanned"))
            {
                to_be_scanned = properties.Metadata["Tobescanned"];
            }
            else
            {
                properties.Metadata["Tobescanned"] = "yes"; 
                blobClient.SetMetadata(properties.Metadata);
                to_be_scanned = "yes";
            }



            // Proceed with remediation of the file only if it was not already scanned
            if (to_be_scanned.Equals("yes"))
            {
                var action = new Remediation(scanResults, log);
                action.Start();
                log.LogInformation($"ScanUploadedBlob function done Processing blob Name:{name} Size: {myBlob.Length} Bytes");
            }

            else
            {
                log.LogInformation($"Blob {name} was already scanned, i.e. it does not need further processing steps");
            }
        }
    }
}
