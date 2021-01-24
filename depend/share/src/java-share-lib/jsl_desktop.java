
import java.awt.Dimension;
import java.awt.BorderLayout;
import java.awt.GridLayout;
import javax.swing.JLabel;
import javax.swing.SwingConstants;
import jshare.option.SOption;
import jshare.gui.SFrame;
import jshare.gui.SMainFrame;
import jshare.gui.SPanel;
import jshare.gui.panel.SMenuPanel;
import jshare.gui.menu.SMenu;
import jshare.gui.menu.SPeerMenu;
import jshare.action.SMainAction;
import jshare.action.SPeerAction;

public class jsl_desktop
{
  public jsl_desktop()
  {
    SFrame frame = new SMainFrame();

/*
    SFrame frame = new SFrame(new SMainAction());
    frame.setDefaultCloseOperation(SFrame.EXIT_ON_CLOSE);

    SLayeredPane mainLayer = new SLayeredPane();
    frame.getContentPane().add(mainLayer);

SMenuPanel peerIndex = new SMenuPanel(mainLayer);
peerIndex.setFloating(SwingConstants.CENTER);

    SMenuPanel menu = new SMenuPanel(mainLayer);
    mainLayer.moveToFront(menu);

    SPeerMenu peer_p = new SPeerMenu(mainLayer);
    menu.addMenu(peer_p);

peer_p.setTarget(peerIndex);
*/


    
   /* 
SMenuPanel peerIndex = new SMenuPanel(mainLayerindexLayer);
peerIndex.addMenu(new SMenu(action));
SPanel peer_p = new SPanel();
peer_p.add(new JLabel("peer_p"));
indexLayer.add(peer_p);
*/



//    frame.pack();
    frame.setSize(new Dimension(SOption.getIntValue(SOption.OPT_MAIN_WIDTH), SOption.getIntValue(SOption.OPT_MAIN_HEIGHT)));
    frame.setVisible(true);

  }
}
