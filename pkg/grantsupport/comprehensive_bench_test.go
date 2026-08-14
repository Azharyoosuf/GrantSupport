package grantsupport_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/adapters/lock"
	"grantsupport/pkg/adapters/ratelimit"
	"grantsupport/pkg/adapters/revocation"
	"grantsupport/pkg/cache"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/grantsupport"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
	"grantsupport/pkg/service"
)

// MetricStats stores calculated percentiles and throughput.
type MetricStats struct {
	Count      int
	Throughput float64
	P50        time.Duration
	P95        time.Duration
	P99        time.Duration
	Min        time.Duration
	Max        time.Duration
	Mean       time.Duration
	Errors     int
}

func calculateStats(durations []time.Duration, totalTime time.Duration, errors int) MetricStats {
	n := len(durations)
	if n == 0 {
		return MetricStats{Errors: errors}
	}

	sort.Slice(durations, func(i, j int) bool {
		return durations[i] < durations[j]
	})

	var sum time.Duration
	for _, d := range durations {
		sum += d
	}

	p50Idx := int(math.Round(0.50 * float64(n-1)))
	p95Idx := int(math.Round(0.95 * float64(n-1)))
	p99Idx := int(math.Round(0.99 * float64(n-1)))

	throughput := float64(n) / totalTime.Seconds()

	return MetricStats{
		Count:      n,
		Throughput: throughput,
		P50:        durations[p50Idx],
		P95:        durations[p95Idx],
		P99:        durations[p99Idx],
		Min:        durations[0],
		Max:        durations[n-1],
		Mean:       sum / time.Duration(n),
		Errors:     errors,
	}
}

// -------------------------------------------------------------
// 1. CPU MICROBENCHMARKS
// -------------------------------------------------------------

func BenchmarkCrypto_TokenGeneration(b *testing.B) {
	b.ReportAllocs()
	buf := make([]byte, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = rand.Read(buf)
		_ = hex.EncodeToString(buf)
	}
}

func BenchmarkCrypto_SHA256Hashing(b *testing.B) {
	b.ReportAllocs()
	token := "6ba7b810-9dad-11d1-80b4-00c04fd430c8_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := sha256.Sum256([]byte(token))
		_ = hex.EncodeToString(h[:])
	}
}

func BenchmarkValidation_GrantSupportInput(b *testing.B) {
	b.ReportAllocs()
	validate := validator.New()
	input := controller.GrantSupportInput{
		DurationMinutes: 60,
		Scope:           "FULL_ACCESS",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validate.Struct(input)
	}
}

// -------------------------------------------------------------
// 2. REAL DATABASE BENCHMARKS (PostgreSQL, MySQL, MariaDB, SQLite)
// -------------------------------------------------------------

func TestRealDatabaseBenchmarks(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	type targetDB struct {
		name       string
		driver     string
		envVar     string
		defaultDSN string
	}

	targets := []targetDB{
		{
			name:       "SQLite (In-Memory)",
			driver:     "sqlite",
			envVar:     "",
			defaultDSN: "file:bench_real_sqlite?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1&_pragma=busy_timeout(5000)",
		},
		{
			name:       "PostgreSQL 16",
			driver:     "pgx",
			envVar:     "TEST_POSTGRES_URL",
			defaultDSN: "postgresql://grantsupport:secretpassword@127.0.0.1:5433/grantsupport?sslmode=disable",
		},
		{
			name:       "MySQL 8.4",
			driver:     "mysql",
			envVar:     "TEST_MYSQL_URL",
			defaultDSN: "grantsupport:secretpassword@tcp(127.0.0.1:3306)/grantsupport?parseTime=true",
		},
		{
			name:       "MariaDB 11",
			driver:     "mysql",
			envVar:     "TEST_MARIADB_URL",
			defaultDSN: "grantsupport:secretpassword@tcp(127.0.0.1:3307)/grantsupport?parseTime=true",
		},
	}

	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			dsn := target.defaultDSN
			if target.envVar != "" && os.Getenv(target.envVar) != "" {
				dsn = os.Getenv(target.envVar)
			}

			db, err := sql.Open(target.driver, dsn)
			if err != nil {
				t.Skipf("Skipping %s: %v", target.name, err)
				return
			}
			defer db.Close()

			db.SetMaxOpenConns(50)
			db.SetMaxIdleConns(25)
			db.SetConnMaxLifetime(5 * time.Minute)

			pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			if err := db.PingContext(pingCtx); err != nil {
				t.Skipf("Skipping %s (unreachable on %s): %v", target.name, dsn, err)
				return
			}

			dialect := "sqlite"
			if target.driver == "pgx" {
				dialect = "postgres"
			} else if target.driver == "mysql" {
				if target.name == "MariaDB 11" {
					dialect = "mariadb"
				} else {
					dialect = "mysql"
				}
			}

			if err := repository.CreateCapabilityTables(ctx, db, dialect); err != nil {
				t.Fatalf("[%s] CreateCapabilityTables failed: %v", target.name, err)
			}

			baseRepo := repository.NewBaseRepositoryWithDB(db, dialect)
			if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
				t.Fatalf("[%s] Schema.Create failed: %v", target.name, err)
			}

			grantRepo := repository.NewSupportGrantRepository(baseRepo)
			auditRepo := repository.NewSecurityAuditRepository(baseRepo)
			lockStore := lock.NewSQLLockStore(db, dialect)
			revStore := revocation.NewSQLRevocationStore(db, dialect)

			svc := service.NewGrantSupportService(grantRepo, auditRepo, lockStore)
			svc.SetRevocationStore(revStore)

			instID := uuid.New()
			adminID := uuid.New()
			agentID := uuid.New()

			// Warm-up 10 iterations
			for i := 0; i < 10; i++ {
				tok, _ := svc.CreateSupportGrant(ctx, instID, adminID, 60)
				if tok != "" {
					_, _, _ = svc.SupportLogin(ctx, tok, agentID)
				}
			}

			// Benchmark 1: CreateSupportGrant (50 samples)
			numOps := 50
			createDurations := make([]time.Duration, 0, numOps)
			createdTokens := make([]string, 0, numOps)
			startTotal := time.Now()

			for i := 0; i < numOps; i++ {
				t0 := time.Now()
				tok, err := svc.CreateSupportGrant(ctx, instID, adminID, 60)
				d := time.Since(t0)
				if err != nil {
					t.Fatalf("CreateSupportGrant failed: %v", err)
				}
				createDurations = append(createDurations, d)
				createdTokens = append(createdTokens, tok)
			}
			createStats := calculateStats(createDurations, time.Since(startTotal), 0)

			// Benchmark 2: SupportLogin (Atomic CAS, Audit Log, Token Version, RS256 JWT)
			loginDurations := make([]time.Duration, 0, numOps)
			startTotal = time.Now()
			for i := 0; i < numOps; i++ {
				t0 := time.Now()
				_, _, err := svc.SupportLogin(ctx, createdTokens[i], agentID)
				d := time.Since(t0)
				if err != nil {
					t.Fatalf("SupportLogin failed: %v", err)
				}
				loginDurations = append(loginDurations, d)
			}
			loginStats := calculateStats(loginDurations, time.Since(startTotal), 0)

			// Benchmark 3: IsTokenRevoked (SQL query)
			revCheckDurations := make([]time.Duration, 0, numOps)
			startTotal = time.Now()
			for i := 0; i < numOps; i++ {
				t0 := time.Now()
				_, err := revStore.IsTokenRevoked(ctx, instID.String(), agentID.String(), 1)
				d := time.Since(t0)
				if err != nil {
					t.Fatalf("IsTokenRevoked failed: %v", err)
				}
				revCheckDurations = append(revCheckDurations, d)
			}
			revCheckStats := calculateStats(revCheckDurations, time.Since(startTotal), 0)

			// Benchmark 4: RevokeSupportGrant
			revokeDurations := make([]time.Duration, 0, 10)
			startTotal = time.Now()
			for i := 0; i < 10; i++ {
				t0 := time.Now()
				err := svc.RevokeSupportGrant(ctx, instID, adminID)
				d := time.Since(t0)
				if err != nil {
					t.Fatalf("RevokeSupportGrant failed: %v", err)
				}
				revokeDurations = append(revokeDurations, d)
			}
			revokeStats := calculateStats(revokeDurations, time.Since(startTotal), 0)

			t.Logf("================================================================")
			t.Logf("DATABASE BENCHMARK: %s", target.name)
			t.Logf("CreateSupportGrant:  Throughput=%6.1f req/s | p50=%8v | p95=%8v | p99=%8v", createStats.Throughput, createStats.P50, createStats.P95, createStats.P99)
			t.Logf("SupportLogin:        Throughput=%6.1f req/s | p50=%8v | p95=%8v | p99=%8v", loginStats.Throughput, loginStats.P50, loginStats.P95, loginStats.P99)
			t.Logf("IsTokenRevoked(SQL): Throughput=%6.1f req/s | p50=%8v | p95=%8v | p99=%8v", revCheckStats.Throughput, revCheckStats.P50, revCheckStats.P95, revCheckStats.P99)
			t.Logf("RevokeSupportGrant:  Throughput=%6.1f req/s | p50=%8v | p95=%8v | p99=%8v", revokeStats.Throughput, revokeStats.P50, revokeStats.P95, revokeStats.P99)
			t.Logf("================================================================")
		})
	}
}

// -------------------------------------------------------------
// 3. REAL REDIS / VALKEY BENCHMARKS
// -------------------------------------------------------------

func TestRealCacheBenchmarks(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	redisURL := "redis://127.0.0.1:6379/0"
	if env := os.Getenv("VALKEY_CACHE_URL"); env != "" {
		redisURL = env
	}

	valkeyClient, err := cache.NewValkeyClient(redisURL)
	if err != nil {
		t.Skipf("Skipping Redis/Valkey benchmark (server unreachable): %v", err)
		return
	}
	defer valkeyClient.Close()

	redisRevStore := revocation.NewRedisRevocationStore(valkeyClient.Client)
	rateLimiter := ratelimit.NewRedisRateLimiter(valkeyClient.Client)

	instID := uuid.New().String()
	userID := uuid.New().String()

	numOps := 100

	// Benchmark 1: Redis IsTokenRevoked
	checkDurations := make([]time.Duration, 0, numOps)
	startTotal := time.Now()
	for i := 0; i < numOps; i++ {
		t0 := time.Now()
		_, err := redisRevStore.IsTokenRevoked(ctx, instID, userID, 1)
		d := time.Since(t0)
		if err != nil {
			t.Fatalf("Redis IsTokenRevoked failed: %v", err)
		}
		checkDurations = append(checkDurations, d)
	}
	checkStats := calculateStats(checkDurations, time.Since(startTotal), 0)

	// Benchmark 2: Redis RevokeUserSessions (Set token version)
	revDurations := make([]time.Duration, 0, numOps)
	startTotal = time.Now()
	for i := 0; i < numOps; i++ {
		t0 := time.Now()
		err := redisRevStore.RevokeUserSessions(ctx, instID, userID, i+2)
		d := time.Since(t0)
		if err != nil {
			t.Fatalf("Redis RevokeUserSessions failed: %v", err)
		}
		revDurations = append(revDurations, d)
	}
	revStats := calculateStats(revDurations, time.Since(startTotal), 0)

	// Benchmark 3: Redis Rate Limiter Allow
	rateDurations := make([]time.Duration, 0, numOps)
	startTotal = time.Now()
	for i := 0; i < numOps; i++ {
		t0 := time.Now()
		_, err := rateLimiter.Allow(ctx, fmt.Sprintf("bench:ip:%d", i%10), 1000, 1*time.Minute)
		d := time.Since(t0)
		if err != nil {
			t.Fatalf("Redis Allow failed: %v", err)
		}
		rateDurations = append(rateDurations, d)
	}
	rateStats := calculateStats(rateDurations, time.Since(startTotal), 0)

	t.Logf("================================================================")
	t.Logf("REDIS / VALKEY BENCHMARK RESULTS")
	t.Logf("IsTokenRevoked:      Throughput=%6.1f req/s | p50=%8v | p95=%8v | p99=%8v", checkStats.Throughput, checkStats.P50, checkStats.P95, checkStats.P99)
	t.Logf("RevokeUserSessions:  Throughput=%6.1f req/s | p50=%8v | p95=%8v | p99=%8v", revStats.Throughput, revStats.P50, revStats.P95, revStats.P99)
	t.Logf("RateLimiter.Allow:   Throughput=%6.1f req/s | p50=%8v | p95=%8v | p99=%8v", rateStats.Throughput, rateStats.P50, rateStats.P95, rateStats.P99)
	t.Logf("================================================================")
}

// -------------------------------------------------------------
// 4. CONCURRENCY BENCHMARKS (1, 10, 50, 100, 250 workers)
// -------------------------------------------------------------

func TestConcurrencyBenchmarks(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:bench_concurrency?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1&_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(100)

	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	concurrencyLevels := []int{1, 10, 50, 100, 250}
	instID := uuid.New()
	adminID := uuid.New()

	for _, concurrency := range concurrencyLevels {
		t.Run(fmt.Sprintf("%d_concurrent_workers", concurrency), func(t *testing.T) {
			numTotalRequests := concurrency * 10
			if numTotalRequests < 100 {
				numTotalRequests = 100
			}

			// Pre-generate tokens
			tokens := make([]string, numTotalRequests)
			for i := 0; i < numTotalRequests; i++ {
				tok, err := engine.CreateSupportGrant(ctx, instID, adminID, 60, "FULL_ACCESS", nil)
				if err != nil {
					t.Fatalf("CreateSupportGrant failed: %v", err)
				}
				tokens[i] = tok
			}

			var wg sync.WaitGroup
			durations := make([]time.Duration, numTotalRequests)
			var errCount int64
			var indexCounter int64

			startTotal := time.Now()

			for w := 0; w < concurrency; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					agentID := uuid.New()

					for {
						idx := int(atomic.AddInt64(&indexCounter, 1) - 1)
						if idx >= numTotalRequests {
							return
						}

						t0 := time.Now()
						_, _, err := engine.SupportLogin(ctx, tokens[idx], agentID)
						d := time.Since(t0)
						durations[idx] = d

						if err != nil {
							atomic.AddInt64(&errCount, 1)
						}
					}
				}()
			}

			wg.Wait()
			totalElapsed := time.Since(startTotal)
			stats := calculateStats(durations, totalElapsed, int(errCount))

			t.Logf("[%3d Workers] SupportLogin: Throughput=%7.1f req/s | p50=%8v | p95=%8v | p99=%8v | Errors=%d",
				concurrency, stats.Throughput, stats.P50, stats.P95, stats.P99, stats.Errors)
		})
	}
}

// -------------------------------------------------------------
// 5. HTTP END-TO-END BENCHMARKS
// -------------------------------------------------------------

func TestHTTPEndToEndBenchmarks(t *testing.T) {
	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:bench_http_e2e?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1&_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(50)

	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	handler := engine.HTTPHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	client := server.Client()

	instID := uuid.New()
	adminID := uuid.New()

	adminJWT, err := security.GenerateJWTWithVersion(adminID.String(), instID.String(), "ADMIN", "FULL_ACCESS", 1, 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWTWithVersion failed: %v", err)
	}

	numOps := 10

	// Benchmark HTTP POST /api/v1/auth/support/grant
	grantDurations := make([]time.Duration, 0, numOps)
	tokens := make([]string, 0, numOps)
	startTotal := time.Now()

	for i := 0; i < numOps; i++ {
		reqBody, _ := json.Marshal(controller.GrantSupportInput{
			DurationMinutes: 60,
			Scope:           "FULL_ACCESS",
		})
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/auth/support/grant", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminJWT)

		t0 := time.Now()
		resp, err := client.Do(req)
		d := time.Since(t0)
		if err != nil || resp.StatusCode != http.StatusCreated {
			t.Fatalf("POST /grant failed: err=%v, code=%d", err, resp.StatusCode)
		}

		var respData struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&respData)
		resp.Body.Close()

		grantDurations = append(grantDurations, d)
		tokens = append(tokens, respData.Token)
	}
	grantStats := calculateStats(grantDurations, time.Since(startTotal), 0)

	// Benchmark HTTP POST /api/v1/auth/support/login
	loginDurations := make([]time.Duration, 0, numOps)
	agentJWTs := make([]string, 0, numOps)
	startTotal = time.Now()

	for i := 0; i < numOps; i++ {
		currentAgentID := uuid.New()
		reqBody, _ := json.Marshal(controller.SupportLoginInput{
			Token:   tokens[i],
			AgentID: currentAgentID.String(),
		})
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/auth/support/login", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")

		t0 := time.Now()
		resp, err := client.Do(req)
		d := time.Since(t0)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("POST /login failed: err=%v, code=%d", err, resp.StatusCode)
		}

		var respData struct {
			AccessToken string `json:"access_token"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&respData)
		resp.Body.Close()

		loginDurations = append(loginDurations, d)
		agentJWTs = append(agentJWTs, respData.AccessToken)
	}
	loginStats := calculateStats(loginDurations, time.Since(startTotal), 0)

	// Benchmark HTTP POST /api/v1/auth/support/logout
	logoutDurations := make([]time.Duration, 0, numOps)
	startTotal = time.Now()

	for i := 0; i < numOps; i++ {
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/auth/support/logout", nil)
		req.Header.Set("Authorization", "Bearer "+agentJWTs[i])

		t0 := time.Now()
		resp, err := client.Do(req)
		d := time.Since(t0)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("POST /logout failed: err=%v, code=%d", err, resp.StatusCode)
		}
		resp.Body.Close()

		logoutDurations = append(logoutDurations, d)
	}
	logoutStats := calculateStats(logoutDurations, time.Since(startTotal), 0)

	t.Logf("================================================================")
	t.Logf("HTTP END-TO-END BENCHMARK RESULTS")
	t.Logf("POST /grant:   Throughput=%6.1f req/s | p50=%8v | p95=%8v | p99=%8v", grantStats.Throughput, grantStats.P50, grantStats.P95, grantStats.P99)
	t.Logf("POST /login:   Throughput=%6.1f req/s | p50=%8v | p95=%8v | p99=%8v", loginStats.Throughput, loginStats.P50, loginStats.P95, loginStats.P99)
	t.Logf("POST /logout:  Throughput=%6.1f req/s | p50=%8v | p95=%8v | p99=%8v", logoutStats.Throughput, logoutStats.P50, logoutStats.P95, logoutStats.P99)
	t.Logf("================================================================")
}

// -------------------------------------------------------------
// 6. DATABASE QUERY PLAN VERIFICATION (EXPLAIN / EXPLAIN ANALYZE)
// -------------------------------------------------------------

func TestDatabaseQueryPlans(t *testing.T) {
	ctx := context.Background()

	// 1. PostgreSQL EXPLAIN ANALYZE
	pgDSN := "postgresql://grantsupport:secretpassword@127.0.0.1:5433/grantsupport?sslmode=disable"
	if env := os.Getenv("TEST_POSTGRES_URL"); env != "" {
		pgDSN = env
	}

	pgDB, err := sql.Open("pgx", pgDSN)
	if err == nil && pgDB.Ping() == nil {
		defer pgDB.Close()
		t.Log("--- PostgreSQL 16 EXPLAIN (ANALYZE, BUFFERS) ---")

		// Query 1: FindActiveGrantByTokenHash
		var plan string
		rows, err := pgDB.QueryContext(ctx, `
			EXPLAIN (ANALYZE, BUFFERS)
			SELECT id, institution_id, token_hash, expires_at, is_used 
			FROM gs_support_grants 
			WHERE token_hash = 'test_hash_lookup' AND is_used = FALSE AND expires_at > CURRENT_TIMESTAMP
		`)
		if err == nil {
			for rows.Next() {
				var line string
				_ = rows.Scan(&line)
				plan += line + "\n"
			}
			rows.Close()
			t.Logf("FindActiveGrantByTokenHash Plan:\n%s", plan)
		}

		// Query 2: IsTokenRevoked
		plan = ""
		rows, err = pgDB.QueryContext(ctx, `
			EXPLAIN (ANALYZE, BUFFERS)
			SELECT token_version FROM gs_revocations 
			WHERE institution_id = '00000000-0000-0000-0000-000000000001' AND user_id = '00000000-0000-0000-0000-000000000002'
		`)
		if err == nil {
			for rows.Next() {
				var line string
				_ = rows.Scan(&line)
				plan += line + "\n"
			}
			rows.Close()
			t.Logf("IsTokenRevoked Plan:\n%s", plan)
		}
	}

	// 2. MySQL EXPLAIN
	myDSN := "grantsupport:secretpassword@tcp(127.0.0.1:3306)/grantsupport?parseTime=true"
	if env := os.Getenv("TEST_MYSQL_URL"); env != "" {
		myDSN = env
	}

	myDB, err := sql.Open("mysql", myDSN)
	if err == nil && myDB.Ping() == nil {
		defer myDB.Close()
		t.Log("--- MySQL 8.4 EXPLAIN ---")

		rows, err := myDB.QueryContext(ctx, `
			EXPLAIN SELECT token_version FROM gs_revocations 
			WHERE institution_id = '00000000-0000-0000-0000-000000000001' AND user_id = '00000000-0000-0000-0000-000000000002'
		`)
		if err == nil {
			cols, _ := rows.Columns()
			t.Logf("MySQL EXPLAIN columns: %v", cols)
			for rows.Next() {
				var id, selectType, table, partitions, pType, possibleKeys, key, keyLen, ref, rowsCount, filtered, extra sql.NullString
				_ = rows.Scan(&id, &selectType, &table, &partitions, &pType, &possibleKeys, &key, &keyLen, &ref, &rowsCount, &filtered, &extra)
				t.Logf("Table: %s | Type: %s | Key: %s | Rows: %s", table.String, pType.String, key.String, rowsCount.String)
			}
			rows.Close()
		}
	}
}
