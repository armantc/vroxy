package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	logger "github.com/xtls/xray-core/common/errors"
)

func InitApi() {
	go func() {
		http.HandleFunc("/api/release", handleRelease)
		http.HandleFunc("/api/disconnect", handleDisconnect)
		http.HandleFunc("/api/sessions", handleSessions)

		println("API server started on 127.0.0.1:8585")
		if err := http.ListenAndServe("127.0.0.1:8585", nil); err != nil {
			logger.LogError(context.Background(), "Server error: ", err.Error())
		}
	}()
}

func handleDisconnect(writer http.ResponseWriter, request *http.Request) {

	if request.Method == http.MethodPost {
		defer request.Body.Close()

		var jsonData DisconnectData
		if err := json.NewDecoder(request.Body).Decode(&jsonData); err != nil || jsonData.Key == "" {
			http.Error(writer, "Invalid JSON", http.StatusBadRequest)
			return
		}

		session, sessionExist := authenticator.sessions.Load(jsonData.Key)

		if sessionExist {
			sessionData := session.(Session)
			authenticator.blockedKeys.Set([]byte(jsonData.Key), []byte("blocked"), blockTTL)
			authenticator.radiusKeys.Del([]byte(jsonData.Key))
			authenticator.inAuthKeys.Delete(jsonData.Key)
			logger.LogError(context.Background(), "Disconnected - Identity: ", sessionData.Identity, " ClientIp: ", sessionData.ClientIp)
		}

		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("OK"))
	} else {
		http.Error(writer, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
}

func handleRelease(writer http.ResponseWriter, request *http.Request) {

	if request.Method == http.MethodPost {
		defer request.Body.Close()

		var jsonData DisconnectData
		if err := json.NewDecoder(request.Body).Decode(&jsonData); err != nil || jsonData.Key == "" {
			http.Error(writer, "Invalid JSON", http.StatusBadRequest)
			return
		}

		authenticator.blockedKeys.Del([]byte(jsonData.Key))

		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("OK"))
	} else {
		http.Error(writer, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
}

func handleSessions(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		json.NewEncoder(writer).Encode(getSessions())
	} else {
		http.Error(writer, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func getSessions() []Session {
	sessions := []Session{}
	keysToRemove := []string{}

	authenticator.sessions.Range(func(key, value interface{}) bool {
		session := value.(Session)

		_, err := authenticator.radiusKeys.Get([]byte(session.Key))

		if err == nil {
			session.LastSync = time.Now().Unix()

			if val, ok := authenticator.trafficMap.Load(key); ok {
				session.Traffic = val.(int64)
			}

			sessions = append(sessions, session)
		}

		if _, ok := authenticator.sockets[session.Key]; !ok {
			keysToRemove = append(keysToRemove, session.Key)
		}

		return true
	})

	for _, key := range keysToRemove {
		cleanupSession(key)
	}

	return sessions
}
func cleanupSession(key string) {
	authenticator.sessions.Delete(key)
	authenticator.trafficMap.Delete(key)
	// delete(authenticator.sockets, key) // sockets are managed separately, so we don't delete them here
}
