import java.security.Provider;
import java.security.Security;
import java.util.Enumeration;

public class t {
  public static void main(String[] args) throws Exception {

 try {   
     Provider p1[] = Security.getProviders();                                  
     int has_aes = 0;                                                         
     int has_rsa = 0;                                                         
     int found = -1;                                                          
     int i = 0;                                                               
     for (i = 0; i < p1.length || found == -1; i++) {                          
         has_aes = 0;                                                         
         has_rsa = 0;                                                         
         for (Enumeration e = p1[i].keys(); e.hasMoreElements();) {            
            String p = e.nextElement().toString();
             if(p.contains("AES")) {                 
                 has_aes = 1;                                                 
                 System.out.println("\t" + p);            
                 System.out.println("\t" + p1[i]);            
                                                                              
             }                                                                
             if (has_aes == 1){// && has_rsa == 1) {                          
                 found = i;                                                   
                 break;                                                       
             }                                                                
             //System.out.println("\t" + e.nextElement());                    
        }
    }
    } catch (Exception e) {
      System.out.println("XD" + e);
    }
  }
}
