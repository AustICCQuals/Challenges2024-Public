package app;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;

public class zFileReader implements Serializable
{
    static final long serialVersionUID = 1L;

    private String path;
    private String contents;

    public zFileReader(String path)
    {
        this.path = path;
        try
        {
            this.contents = new String(Files.readAllBytes(Paths.get(path)));
        }
        catch (IOException e)
        {
            System.out.println("Error reading file: " + path);
            this.contents = "";
        }
    }

    private void readObject(ObjectInputStream inputStream) throws IOException, ClassNotFoundException
    {
        inputStream.defaultReadObject();
        this.contents = new String(Files.readAllBytes(Paths.get(path)));
        System.out.println("read file: " + path);
    }

    public String getPath()
    {
        return path;
    }

    public String getContents(){
        return contents;
    }

    public String toString()
    {
        return "{\"path\":\"" + path + "\",\"contents\":\"" + contents + "\"}";
    }

    public void setPath(String path)
    {
        this.path = path;
    }

    public void setContents(String contents)
    {
        this.contents = contents;
    }

}