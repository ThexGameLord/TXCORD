package to.uk.thexgamelord.txcord;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.server.ServerLoadEvent;

import org.bukkit.configuration.file.FileConfiguration;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;


public final class Txcordconnect extends JavaPlugin implements Listener {

    @Override
    public void onEnable() {
        Bukkit.getPluginManager().registerEvents(this, this);

        // Check if the config file exists, and create it if it doesn't
        if (!getDataFolder().exists()) {
            getDataFolder().mkdir();
        }
        File configFile = new File(getDataFolder(), "config.yml");
        if (!configFile.exists()) {
            saveDefaultConfig();
            getLogger().info("[txcordconnect] Generating");
        }

        // Load the config
        reloadConfig();

        // Read the API IP address from the config file
        FileConfiguration config = getConfig();
        String apiAddress = config.getString("apiAddress");
        String Authkey = config.getString("Authkey");
        int PDELAY = config.getInt("Delay");
        getLogger().info("[txcordconnect] Using " + apiAddress + " For api");

        TimerTask task = new TimerTask() {
            @Override
            public void run() {
                // Retrieve server information
                String MOTD = Bukkit.getServer().getMotd();
                int playerCount = Bukkit.getServer().getOnlinePlayers().size();
                int maxPlayerCount = Bukkit.getServer().getMaxPlayers();
                String serverVersion = Bukkit.getServer().getVersion();
                double[] TPS = Bukkit.getTPS();

                // Retrieve player names
                List<String> playerNames = new ArrayList<>();
                for (Player player : Bukkit.getServer().getOnlinePlayers()) {
                    playerNames.add(player.getName());
                }

                // Prepare JSON payload with server information
                String payload = "{\"playerCount\": " + playerCount + ", \"maxPlayerCount\": " + maxPlayerCount
                        + ", \"serverVersion\": \"" + serverVersion + "\", \"Motd\": \"" + MOTD + "\", \"Ticks\": \"" + TPS + "\"}";
                String playerNamesPayload = "{\"PlayerNames\": " + convertListToJson(playerNames) + "}";

                // Make POST request to API endpoint for server information
                try {
                    URL url = new URL(apiAddress + "/api/main");
                    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                    connection.setRequestMethod("POST");
                    connection.setRequestProperty("Content-Type", "application/json");
                    connection.setRequestProperty("Authkey", Authkey); // Add the Authkey header
                    connection.setDoOutput(true);

                    try (OutputStream outputStream = connection.getOutputStream()) {
                        byte[] input = payload.getBytes(StandardCharsets.UTF_8);
                        outputStream.write(input, 0, input.length);
                    }

                    int responseCode = connection.getResponseCode();
                    getLogger().info("[txcordconnect] API responded with: " + responseCode);
                    // Handle the API response code as needed
                } catch (IOException e) {
                    e.printStackTrace();
                }

// Make POST request to API endpoint for player names
                try {
                    URL url = new URL(apiAddress + "/api/playernames");
                    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                    connection.setRequestMethod("POST");
                    connection.setRequestProperty("Content-Type", "application/json");
                    connection.setRequestProperty("Authkey", Authkey); // Add the Authkey header
                    connection.setDoOutput(true);

                    try (OutputStream outputStream = connection.getOutputStream()) {
                        byte[] input = playerNamesPayload.getBytes(StandardCharsets.UTF_8);
                        outputStream.write(input, 0, input.length);
                    }

                    int responseCode = connection.getResponseCode();
                    getLogger().info("[txcordconnect] API responded with: " + responseCode);
                    // Handle the API response code as needed
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        };

        // Schedule the task to run every 1 minute (60 seconds)
        Timer timer = new Timer();
        timer.schedule(task, 0, PDELAY/60000);

    }

    private String convertListToJson(List<String> list) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < list.size(); i++) {
            sb.append("\"").append(list.get(i)).append("\"");
            if (i < list.size() - 1) {
                sb.append(",");
            }
        }
        sb.append("]");
        return sb.toString();
    }

    @EventHandler
    public void onServerLoad(ServerLoadEvent event) {
        // Start the timer task when the server has finished loading
        TimerTask task = new TimerTask() {
            @Override
            public void run() {
                // Your task logic here
            }
        };

        // Schedule the task to run every 1 minute (60 seconds)
        Timer timer = new Timer();
        timer.schedule(task, 0, 60000);
    }
}
