package app;

import static spark.Spark.*;
import java.util.Base64;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.io.ObjectOutputStream;
import java.io.ByteArrayOutputStream;

public class App {

    public static void main(String[] args) {

        get("/", (request, response) -> {
            zFileReader index = new zFileReader("/app/index.html");
            return index.getContents();
        });
        
        before("/*", (request, response) -> {
            // allow for pre-flight requests to return 200 
            if (request.requestMethod() == "OPTIONS") {
                return;
            }
            if (request.pathInfo().equals("/") || request.pathInfo().equals("/health")) {
                return;
            }
            if (!System.getenv("API_KEY").equals(request.headers("API_KEY"))) {
                halt(401, "You are not welcome here");
            }
        });
        
        get("/health", (request, response) -> {
            return "OK";
        });

        get("/getFile", (request, response) -> {
            // get the base64 encoded string from the data parameter
            String base64EncodedString = request.queryParams("data");
            // decode the base64 encoded string
            byte[] decodedBytes = Base64.getDecoder().decode(base64EncodedString);
            // deserialise decodedBytes into an object
            ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(decodedBytes));
            Object object = in.readObject();
            return object.toString();
        });

        options("/*", (request, response) -> {
            return "200";
        });
    }
}