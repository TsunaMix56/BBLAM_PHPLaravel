# BBLAM PHP Laravel - Docker & Kubernetes Deployment

## 📋 สารบัญ
- [ภาพรวมระบบ](#ภาพรวมระบบ)
- [สถาปัตยกรรม](#สถาปัตยกรรม)
- [การติดตั้ง Docker](#การติดตั้ง-docker)
- [การติดตั้ง Kubernetes](#การติดตั้ง-kubernetes)
- [คำสั่งที่ใช้งาน](#คำสั่งที่ใช้งาน)

---

## 🎯 ภาพรวมระบบ

โปรเจคนี้เป็น **JWT-Protected REST API** ที่พัฒนาด้วย PHP Laravel พร้อม:
- ✅ JWT Authentication (HS256)
- ✅ SQL Server Database
- ✅ Docker Containerization
- ✅ Kubernetes Orchestration
- ✅ Multi-stage Build (Optimized)

---

## 🏗️ สถาปัตยกรรม

### **Docker Architecture**
```
┌─────────────────────────────────────┐
│  Nginx (Port 8000)                  │
│  - Reverse Proxy                    │
│  - Static File Serving              │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│  PHP-FPM 8.3                        │
│  - Laravel Framework                │
│  - JWT Authentication               │
│  - api.php (Standalone API)         │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│  SQL Server 2022 Express            │
│  - Database: LOGIN_TEST             │
│  - Table: T_User                    │
└─────────────────────────────────────┘
```

### **Kubernetes Architecture**
```
┌────────────────────────────────────────────┐
│  LoadBalancer Service (Port 30080)         │
└──────────────┬─────────────────────────────┘
               │
┌──────────────▼─────────────────────────────┐
│  Deployment: bblam-php-app (3 replicas)    │
│  ┌──────────────┐  ┌──────────────────┐   │
│  │  Nginx:80    │  │  PHP-FPM:9000    │   │
│  └──────────────┘  └──────────────────┘   │
└──────────────┬─────────────────────────────┘
               │
┌──────────────▼─────────────────────────────┐
│  StatefulSet: SQL Server                   │
│  - Persistent Volume: 10Gi                 │
└────────────────────────────────────────────┘
```

---

## 🐳 การติดตั้ง Docker

### **1. ตรวจสอบความพร้อม**
```powershell
# ตรวจสอบ Docker
docker --version

# ตรวจสอบ Docker Compose
docker-compose --version
```

### **2. Build Docker Image**
```powershell
# เข้าไปยังโฟลเดอร์โปรเจค
cd D:\BBLAM_PHPLaravel\BBLAM_PHPLaravel

# Build image (Multi-stage optimized)
docker build -t bblam-php-app:latest .
```

**สิ่งที่เกิดขึ้นใน Build:**
- 📦 Stage 1: ติดตั้ง dependencies ด้วย Composer
- 🔧 Stage 2: Copy เฉพาะไฟล์ที่จำเป็น (ไม่มี dev dependencies)
- ⚡ Optimize: Config cache, Route cache, View cache
- 🔒 Security: Set permissions สำหรับ storage/

### **3. รัน Docker Compose**
```powershell
# รันทุก service พร้อมกัน (Nginx + PHP + SQL Server)
docker-compose up -d

# ดูสถานะ containers
docker-compose ps

# ดู logs
docker-compose logs -f app
```

### **4. ทดสอบ API**
```powershell
# ทดสอบผ่าน Nginx
curl http://localhost:8000/api/auth/token `
  -H "Authorization: Basic dGVzdDIzNDU6MTIzNA=="
```

### **5. จัดการ Containers**
```powershell
# หยุด services
docker-compose down

# หยุดและลบ volumes (ระวัง: จะลบข้อมูล SQL Server)
docker-compose down -v

# Restart service เดียว
docker-compose restart app
```

---

## ☸️ การติดตั้ง Kubernetes

### **1. เตรียม Kubernetes Cluster**

**สำหรับ Windows (Docker Desktop):**
```powershell
# เปิด Kubernetes ใน Docker Desktop Settings
# Settings > Kubernetes > Enable Kubernetes

# ตรวจสอบ
kubectl version --client
kubectl cluster-info
kubectl get nodes
```

**สำหรับ Minikube:**
```powershell
# เริ่ม cluster
minikube start --driver=docker

# ตรวจสอบ
kubectl get nodes
```

### **2. Load Docker Image เข้า Kubernetes**

**Docker Desktop:**
```powershell
# Image จาก local registry จะพร้อมใช้งานอัตโนมัติ
docker images | Select-String bblam-php-app
```

**Minikube:**
```powershell
# Load image เข้า Minikube
minikube image load bblam-php-app:latest

# ตรวจสอบ
minikube image ls | Select-String bblam
```

### **3. Deploy ไปยัง Kubernetes**
```powershell
# สร้าง namespace (optional)
kubectl create namespace bblam-app

# Apply configuration files
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/sqlserver-statefulset.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/deployment.yaml
```

**สิ่งที่เกิดขึ้น:**
1. 🔐 **Secret**: เก็บ DB password, JWT secret (base64 encoded)
2. ⚙️ **ConfigMap**: เก็บ environment variables
3. 💾 **StatefulSet**: Deploy SQL Server พร้อม persistent storage
4. 🌐 **Service**: สร้าง internal DNS และ LoadBalancer
5. 🚀 **Deployment**: Deploy PHP app 3 replicas พร้อม Nginx sidecar

### **4. ตรวจสอบสถานะ**
```powershell
# ดู pods
kubectl get pods

# ดู services
kubectl get services

# ดู deployments
kubectl get deployments

# ดู logs ของ pod
kubectl logs -f <pod-name> -c php-fpm
kubectl logs -f <pod-name> -c nginx
```

### **5. เข้าถึง Application**

**Docker Desktop Kubernetes:**
```powershell
# LoadBalancer จะใช้ localhost
curl http://localhost:30080/api/auth/token `
  -H "Authorization: Basic dGVzdDIzNDU6MTIzNA=="
```

**Minikube:**
```powershell
# เปิด tunnel สำหรับ LoadBalancer
minikube service bblam-php-service --url

# หรือใช้ port-forward
kubectl port-forward service/bblam-php-service 8080:80

# ทดสอบ
curl http://localhost:8080/api/auth/token `
  -H "Authorization: Basic dGVzdDIzNDU6MTIzNA=="
```

### **6. Scale Application**
```powershell
# เพิ่ม replicas
kubectl scale deployment bblam-php-app --replicas=5

# ดูสถานะ
kubectl get pods -w
```

### **7. Update Deployment**
```powershell
# Build image ใหม่
docker build -t bblam-php-app:v2 .

# Tag image
docker tag bblam-php-app:v2 bblam-php-app:latest

# Load เข้า Minikube (ถ้าใช้)
minikube image load bblam-php-app:latest

# Rolling update
kubectl rollout restart deployment/bblam-php-app

# ดูสถานะการ update
kubectl rollout status deployment/bblam-php-app
```

### **8. Debug & Troubleshooting**
```powershell
# เข้าไปใน pod
kubectl exec -it <pod-name> -c php-fpm -- /bin/bash

# ดู events
kubectl get events --sort-by='.lastTimestamp'

# ดู describe pod
kubectl describe pod <pod-name>

# ดู logs ทั้งหมด
kubectl logs -f deployment/bblam-php-app --all-containers=true
```

### **9. ลบ Deployment**
```powershell
# ลบทีละไฟล์
kubectl delete -f k8s/deployment.yaml
kubectl delete -f k8s/service.yaml
kubectl delete -f k8s/sqlserver-statefulset.yaml
kubectl delete -f k8s/configmap.yaml
kubectl delete -f k8s/secret.yaml

# หรือลบทั้งหมดในโฟลเดอร์
kubectl delete -f k8s/
```

---

## 📊 คำสั่งที่ใช้งานบ่อย

### **Docker Commands**
```powershell
# ดู running containers
docker ps

# ดู images
docker images

# ดู container logs
docker logs -f <container-id>

# เข้าไปใน container
docker exec -it <container-id> /bin/bash

# ลบ unused images/containers
docker system prune -a
```

### **Kubernetes Commands**
```powershell
# Get resources
kubectl get all
kubectl get pods -o wide
kubectl get services

# Describe resources
kubectl describe pod <pod-name>
kubectl describe service <service-name>

# Port forwarding
kubectl port-forward pod/<pod-name> 8080:80

# Copy files
kubectl cp <pod-name>:/path/in/pod ./local-path

# Execute commands
kubectl exec <pod-name> -- php artisan --version
```

---

## 🔧 Configuration Files

### **ไฟล์สำคัญ:**
- `Dockerfile` - Multi-stage build สำหรับ PHP app
- `docker-compose.yml` - Local development environment
- `docker/nginx/default.conf` - Nginx reverse proxy config
- `.dockerignore` - ไฟล์ที่ไม่ต้อง copy เข้า image
- `k8s/deployment.yaml` - Kubernetes deployment + nginx sidecar
- `k8s/service.yaml` - LoadBalancer + ClusterIP services
- `k8s/sqlserver-statefulset.yaml` - SQL Server with persistent volume
- `k8s/configmap.yaml` - Environment variables
- `k8s/secret.yaml` - Sensitive data (passwords, keys)

---

## 🔐 Security Notes

1. **Production Secrets**: เปลี่ยน passwords และ JWT secret ใน `k8s/secret.yaml`
2. **SQL Server Password**: ต้องมีความซับซ้อนตาม policy (ตัวพิมพ์ใหญ่/เล็ก + ตัวเลข + สัญลักษณ์)
3. **Image Registry**: สำหรับ production ควรใช้ private registry
4. **RBAC**: ตั้งค่า Role-Based Access Control สำหรับ K8s cluster

---

## 📝 API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/auth/token` | รับ JWT token | Basic Auth |
| POST | `/api/auth/create-account` | สร้างผู้ใช้ใหม่ | JWT Bearer |
| POST | `/api/auth/login` | Login | JWT Bearer |

**ตัวอย่างการใช้งาน:**
```powershell
# 1. ขอ JWT Token
$token = (curl http://localhost:8000/api/auth/token `
  -H "Authorization: Basic dGVzdDIzNDU6MTIzNA==" | ConvertFrom-Json).data.access_token

# 2. Login
curl http://localhost:8000/api/auth/login `
  -H "Authorization: Bearer $token" `
  -H "Content-Type: application/json" `
  -d '{"username":"test2345","password":"1234"}'
```

---

## 🎓 อธิบายเทคโนโลยี

### **Docker คืออะไร?**
- **Container Platform**: แพ็คแอปพลิเคชันพร้อม dependencies ทั้งหมดในหน่วยเดียว
- **Portable**: รันได้เหมือนกันทุก environment (dev/staging/prod)
- **Isolated**: แต่ละ container แยกกันไม่รบกวนกัน
- **Lightweight**: เบากว่า Virtual Machine

### **Kubernetes คืออะไร?**
- **Container Orchestration**: จัดการ containers จำนวนมาก
- **Auto-scaling**: เพิ่ม/ลด pods ตามความต้องการ
- **Self-healing**: Restart pods ที่ crash อัตโนมัติ
- **Load Balancing**: กระจาย traffic ไปยัง pods
- **Rolling Updates**: Update แอปไม่ downtime

### **Multi-stage Build คืออะไร?**
ใช้หลาย stage ใน Dockerfile เพื่อ:
1. **Stage 1 (Builder)**: ติดตั้ง dependencies ทั้งหมด
2. **Stage 2 (Runtime)**: Copy เฉพาะไฟล์ที่จำเป็น
3. **ผลลัพธ์**: Image size เล็กลง, ปลอดภัยขึ้น

---

## 🚀 Quick Start

**Docker:**
```powershell
docker-compose up -d
curl http://localhost:8000/api/auth/token -H "Authorization: Basic dGVzdDIzNDU6MTIzNA=="
```

**Kubernetes:**
```powershell
kubectl apply -f k8s/
kubectl get pods -w
# รอจน pods เป็น Running
curl http://localhost:30080/api/auth/token -H "Authorization: Basic dGVzdDIzNDU6MTIzNA=="
```

---

## 📞 Support

หากมีปัญหาในการ deploy:
1. ตรวจสอบ logs: `docker logs` หรือ `kubectl logs`
2. ตรวจสอบ resources: `kubectl describe pod`
3. ตรวจสอบ network: `kubectl get services`
4. ตรวจสอบ storage: `kubectl get pv,pvc`

---

**สร้างโดย:** BBLAM Development Team  
**วันที่:** November 12, 2025  
**Version:** 1.0.0
