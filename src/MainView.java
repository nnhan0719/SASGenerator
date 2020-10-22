import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.BoxLayout;
import javax.swing.JTextField;
import javax.swing.JLabel;
import java.awt.FlowLayout;
import java.awt.BorderLayout;
import javax.swing.JPanel;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.awt.event.ActionEvent;
import javax.swing.JTextArea;

public class MainView {

	private JFrame frame;
	private JPanel panel_input;
	private JPanel panel_result;
	private JTextField txtAccessPolicies;
	private JTextField txtDayExpiration;
	
	private JButton btnGit;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					MainView window = new MainView();
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public MainView() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame("SAS Token Generator");
		frame.setBounds(100, 100, 450, 300);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);
		frame.setResizable(false);
		
		panel_input = new JPanel();
		panel_input.setBounds(6, 5, 438, 83);
		frame.getContentPane().add(panel_input);
		panel_input.setLayout(null);
		
		txtAccessPolicies = new JTextField();
		txtAccessPolicies.setBounds(121, 5, 311, 26);
		panel_input.add(txtAccessPolicies);
		txtAccessPolicies.setColumns(10);
		
		JLabel lblAccessPolicies = new JLabel("Access Policies:");
		lblAccessPolicies.setBounds(6, 10, 103, 16);
		panel_input.add(lblAccessPolicies);
		
		JLabel lblDayExpiration = new JLabel("No of Days:");
		lblDayExpiration.setBounds(6, 48, 103, 16);
		panel_input.add(lblDayExpiration);
		
		txtDayExpiration = new JTextField();
		txtDayExpiration.addKeyListener(new KeyAdapter() {
			public void keyTyped(KeyEvent e) {
				char c = e.getKeyChar();
			      if (!((c >= '0') && (c <= '9') ||
			         (c == KeyEvent.VK_BACK_SPACE) ||
			         (c == KeyEvent.VK_DELETE))) {
			        e.consume();
			      }
			}
		});
		
		txtDayExpiration.setColumns(10);
		txtDayExpiration.setBounds(121, 43, 311, 26);
		panel_input.add(txtDayExpiration);
		
		panel_result = new JPanel();
		panel_result.setBounds(6, 120, 438, 119);
		frame.getContentPane().add(panel_result);
		panel_result.setLayout(null);
		
		JTextArea txtSasToken = new JTextArea();
		txtSasToken.setEditable(false);
		txtSasToken.setLineWrap(true);
		txtSasToken.setWrapStyleWord(true);
		txtSasToken.setBounds(6, 6, 426, 107);
		panel_result.add(txtSasToken);
		
		JButton btnGenerate = new JButton("Generate");
		btnGenerate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String dayString = txtDayExpiration.getText();
				int day = 0;
				
				if (dayString.isEmpty()) {
					day = Integer.valueOf(dayString.isEmpty() ? "1" : dayString);
					txtDayExpiration.setText(day + "");
				}
				
				String[] array = SplitString(txtAccessPolicies.getText());
				if (array.length == 3) {
					String result = GetSASToken(array[0], array[1], array[2], day);
					txtSasToken.setText(result);
//					txtSasToken.setText(array[0] +"+++"+ array[1] +"+++"+ array[2]);
				} else {
					txtSasToken.setText("Access Policies is invalid");
				}
			}
		});
		btnGenerate.setBounds(6, 89, 438, 29);
		frame.getContentPane().add(btnGenerate);
		
		btnGit = new JButton("Git");
		btnGit.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					java.awt.Desktop.getDesktop().browse(new URI("https://github.com/nnhan0719"));
				} catch (Exception exception) {
					
				}
			}
		});
		btnGit.setBounds(381, 243, 63, 29);
		frame.getContentPane().add(btnGit);
	}
	
	private static String GetSASToken(String resourceUri, String keyName, String key, int day)
	  {
	      long epoch = System.currentTimeMillis()/1000L;
//	      int week = 60*60*24*7;
	      int week = 60*60*24*day;
	      String expiry = Long.toString(epoch + week);

	      String sasToken = null;
	      try {
	          String stringToSign = URLEncoder.encode(resourceUri, "UTF-8") + "\n" + expiry;
	          String signature = getHMAC256(key, stringToSign);
	          sasToken = "SharedAccessSignature sr=" + URLEncoder.encode(resourceUri, "UTF-8") +"&sig=" +
	                  URLEncoder.encode(signature, "UTF-8") + "&se=" + expiry + "&skn=" + keyName;
	      } catch (UnsupportedEncodingException e) {

	          e.printStackTrace();
	      }

	      return sasToken;
	  }


	public static String getHMAC256(String key, String input) {
	    Mac sha256_HMAC = null;
	    String hash = null;
	    try {
	        sha256_HMAC = Mac.getInstance("HmacSHA256");
	        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes(), "HmacSHA256");
	        sha256_HMAC.init(secret_key);
	        Encoder encoder = Base64.getEncoder();

	        hash = new String(encoder.encode(sha256_HMAC.doFinal(input.getBytes("UTF-8"))));

	    } catch (InvalidKeyException e) {
	        e.printStackTrace();
	    } catch (NoSuchAlgorithmException e) {
	        e.printStackTrace();
	    } catch (IllegalStateException e) {
	        e.printStackTrace();
	    } catch (UnsupportedEncodingException e) {
	        e.printStackTrace();
	    }

	    return hash;
	}
	
	private static String[] SplitString(String accessPolicies) {
		try {
			String[] array = accessPolicies.split(";");
			array[0] = array[0].replace("Endpoint=sb://", "").replace("/", "");
			array[1] = array[1].replace("SharedAccessKeyName=", "");
			array[2] = array[2].replace("SharedAccessKey=", "");
			return array;
		} catch (Exception e) {
			return new String[] {};
		}
	}
}
