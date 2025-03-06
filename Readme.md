# O2 IMS: Implementation

```
Status: In progress
Created time: December 25, 2024 4:28 PM
Tag: K8S, O2, OSC
```


## Introduction

## Progress


> ⚠️ Will Migrate the logs from Outline soon…

> **Tracker**
> - [ ]  Create IMS agent module
> - [x]  DHCP Handler
> - [x]  Database connector
> - [x]  Define API call to be used
> - [x]  Create IMS API handler for FOCOM
>     - [x]  Salvage API from current OSC’s IMS proposal
>         - Take only the ones that is not useless
>     - [x]  Database connector between IMS-Worker  and IMS-API

### Implementation Topology

```mermaid
graph TB
    %% Frontend Components
    UI[SvelteKit Frontend]
    UI_CLUSTERS[Clusters Management]
    UI_MACHINES[Machines Management]
    UI_WORKERS[Workers Dashboard]
    
    %% Backend Components
    API[Django REST API]
    DB[(PostgreSQL Database)]
    AUTH[JWT Authentication]
    
    %% IMS Worker Components
    W1[IMS Worker 1]
    W2[IMS Worker 2]
    WN[IMS Worker N]
    
    %% Worker Services
    DHCP1[DHCP Service]
    TFTP1[TFTP Service]
    
    %% Network Components
    CLIENT[Network Clients]
    
    %% Frontend Relationships
    UI --> |HTTP/REST| API
    UI --- UI_CLUSTERS
    UI --- UI_MACHINES
    UI --- UI_WORKERS
    
    %% Backend Relationships
    API --> |CRUD| DB
    API --> |Verify| AUTH
    
    %% Worker Authentication
    W1 --> |JWT Auth| AUTH
    W2 --> |JWT Auth| AUTH
    WN --> |JWT Auth| AUTH
    
    %% Worker Registration & Updates
    W1 --> |Register/Heartbeat| API
    W2 --> |Register/Heartbeat| API
    WN --> |Register/Heartbeat| API
    
    %% Worker Services
    W1 --- DHCP1
    W1 --- TFTP1
    
    %% Client Interactions
    CLIENT --> |DHCP Request| DHCP1
    CLIENT --> |TFTP Request| TFTP1
    
    %% Database Relations
    subgraph Database
        DB --- DB_CLUSTERS[(Clusters)]
        DB --- DB_MACHINES[(Machines)]
        DB --- DB_LEASES[(DHCP Leases)]
        DB --- DB_WORKERS[(Workers)]
    end
    
    %% Worker States
    subgraph Worker States
        WS_ACTIVE[Active]
        WS_INACTIVE[Inactive]
        WS_ERROR[Error]
    end
    
    %% Component Types
    classDef frontend fill:#f9f,stroke:#333,stroke-width:2px
    classDef backend fill:#bbf,stroke:#333,stroke-width:2px
    classDef worker fill:#bfb,stroke:#333,stroke-width:2px
    classDef database fill:#fbb,stroke:#333,stroke-width:2px
    
    %% Apply Classes
    class UI,UI_CLUSTERS,UI_MACHINES,UI_WORKERS frontend
    class API,AUTH backend
    class W1,W2,WN,DHCP1,TFTP1 worker
    class DB,DB_CLUSTERS,DB_MACHINES,DB_LEASES,DB_WORKERS database
```

```mermaid
graph LR
    %% SMO Components
    SMO[Service Management and Orchestration]
    NONRT[Non-RT RIC]
    R_APP[rApp]
    OSC[O-RAN Software Controller]
    
    %% IMS Components
    IMS_API[IMS API Server]
    IMS_UI[IMS Dashboard]
    IMS_W1[IMS Worker 1]
    IMS_W2[IMS Worker 2]
    
    %% FCAPS Components
    FOCOM[FCAPS O&M]
    FM[Fault Management]
    CM[Configuration Management]
    PM[Performance Management]
    
    %% Network Functions
    CU_CP[O-RAN CU-CP]
    CU_UP[O-RAN CU-UP]
    DU[O-RAN DU]
    RU[O-RAN RU]
    
    %% Interfaces
    O2_IMS[O2 IMS Interface]
    O2_DMS[O2 DMS Interface]
    
    %% Relationships
    SMO --- NONRT
    SMO --- FOCOM
    SMO --- OSC
    
    NONRT --- R_APP
    
    %% IMS Integration
    OSC --- O2_IMS
    O2_IMS --- IMS_API
    IMS_API --- IMS_UI
    IMS_API --- IMS_W1
    IMS_API --- IMS_W2
    
    %% FCAPS
    FOCOM --- FM
    FOCOM --- CM
    FOCOM --- PM
    
    %% O2 Interface Connections
    OSC --- O2_DMS
    O2_DMS --- CU_CP
    O2_DMS --- CU_UP
    O2_DMS --- DU
    O2_DMS --- RU
    
    %% Worker Connections
    IMS_W1 -.->|DHCP/TFTP| CU_CP
    IMS_W1 -.->|DHCP/TFTP| CU_UP
    IMS_W2 -.->|DHCP/TFTP| DU
    IMS_W2 -.->|DHCP/TFTP| RU
    
    %% Subgraphs
    subgraph "Service Management and Orchestration Layer"
        SMO
        NONRT
        R_APP
        OSC
        FOCOM
    end
    
    subgraph "Infrastructure Management System"
        IMS_API
        IMS_UI
        IMS_W1
        IMS_W2
    end
    
    subgraph "O-RAN Network Functions"
        CU_CP
        CU_UP
        DU
        RU
    end
    
    %% Styling
    classDef smo fill:#f9f,stroke:#333,stroke-width:2px
    classDef ims fill:#bfb,stroke:#333,stroke-width:2px
    classDef nf fill:#bbf,stroke:#333,stroke-width:2px
    classDef interface fill:#fbb,stroke:#333,stroke-width:2px
    
    class SMO,NONRT,R_APP,OSC,FOCOM smo
    class IMS_API,IMS_UI,IMS_W1,IMS_W2 ims
    class CU_CP,CU_UP,DU,RU nf
    class O2_IMS,O2_DMS interface
```

### Implementation Flow

```mermaid
sequenceDiagram

    participant BN as Bare Metal
    participant IW as IMS-worker
 

    participant API as IMS-API & DB
    participant UI as IMS-UI
    

    UI->>API: Add Cluster
    UI->>API: Add Machine to Cluster

    API->>IW: Update the DHCP broadcast status (Allow if machine registered)
    IW->>BN: DHCP 
    BN->>IW: DHCP Request
    BN->>IW: DHCP Req/ACK
    
    BN->>IW: TFTP Request
    IW->>BN: Send boot file (TFTP)
    
    IW->>BN: Check cluster status
    
    IW->>API: Report Cluster Status
    		Note over BN,IW: Installation Process...
    IW->>API: Update table on database
    
    API->>UI: Update/Show Device Status
    
    
```

```mermaid
sequenceDiagram

    participant BM as Bare Metal
    participant IW as IMS-worker
 
    participant API as IMS-API
    participant UI as IMS-UI
    
    UI->>API: Add Cluster
    UI->>API: Add Machine to Cluster
    
    Note over BM,API: <--->
    IW->>API: Worker Registration
    API->>IW: Token
    IW->>API: Send Heartbeat
    API->>UI: Worker Heartbeat

    Note over BM,API: Provisioining Phase
    BM->>IW: DHCP Discover
    IW->>API: Request for Cluster Information
    API->>IW: Send cluster detail (Machine info.)

    Note over BM,IW: PXE Phase
    BM->>IW: DHCP Request (MAC Address)
    IW->>BM: DHCP Offer (Based on API Data )
    BM->>IW: DHCP Acknowledgement
    IW->>API: New Machine status (Could be sent through Heartbeat)
    BM->>IW: PXE Boot (Request for file)
    IW->>BM: Send PXE deploy kernel, ramdisk and config
    BM->>BM: Runs agent ramdisk, start OS Installation
    BM->>BM: Reboot
    BM->>API: Heartbeat (Optional)
    API->>UI: Update machine status

```

### IMS-UI

- Need some way to allow admin to interacte with the IMS-Worker.
- IMS-UI will allow user to create cluster and add machines. This machines will be accepted by the IMS-Worker to perform netboot operation, thus starting the provisioning sequence.
    
    [Screencast From 2024-12-26 16-15-31.mp4](assets/Screencast_From_2024-12-26_16-15-31.mp4)
    
- Login Page for authentication purpose. The same token will also be applied towards IMS-Worker on the Edge side.
    
    [Screencast From 2024-12-30 17-32-55.mp4](assets/Screencast_From_2024-12-30_17-32-55.mp4)
    

### IMS-API

**Viewsets Definition**

| ViewSet  | Correspondent Function/Class  |
| --- | --- |
| IPPoolViewset | class IPPoolViewSet(viewsets.ModelViewSet): |
| LeaseViewset | class LeaseViewSet(viewsets.ModelViewSet): |
| DHCPConfigViewset | class DHCPConfigViewSet(viewsets.ModelViewSet): |
| TFTPConfigViewset | class TFTPConfigViewSet(viewsets.ModelViewSet): |

**API Definition**

| API | Context | Context | Status |
| --- | --- | --- | --- |
| **api/machines/** | POST,GET | View all machines | ✅ Implemented |
| **api/machines/{ID}** | POST,GET |  | ✅ Implemented |
| **api/cluster/** | GET | View all cluster | ✅ Implemented |
| **api/cluster/{ID}/add_machine** | POST | Add machine into cluster | ✅ Implemented |

# Database Schema

## Infrastructure Models

### Cluster
| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| id | Integer | Primary Key, Auto-increment |  |
| name | CharField | max_length=100 |  |
| description | TextField |  |  |
| status | CharField | max_length=20, choices | OPERATIONAL, DEGRADED, CRITICAL, MAINTENANCE, SCALING, UPGRADING, UNKNOWN |
| health | CharField | max_length=20, choices | HEALTHY, WARNING, CRITICAL, UNKNOWN |
| created_at | DateTimeField | auto_now_add=True |  |
| updated_at | DateTimeField | auto_now=True |  |

### Machine
| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| id | Integer | Primary Key, Auto-increment |  |
| cluster | ForeignKey | Cluster, CASCADE |  |
| hostname | CharField | max_length=100 |  |
| ip | GenericIPAddressField |  |  |
| mac | CharField | max_length=17 | Format: XX:XX:XX:XX:XX:XX |
| cpu_cores | IntegerField |  |  |
| role | CharField | max_length=20, choices | MASTER, WORKER, STORAGE, GATEWAY |
| os_type | CharField | max_length=20, choices | LINUX, WINDOWS, MACOS |
| status | CharField | max_length=20, choices | ACTIVE, INACTIVE, MAINTENANCE, ERROR, DEPLOYING, UPGRADING, UNREACHABLE |
| health | CharField | max_length=20, choices | HEALTHY, WARNING, CRITICAL, UNKNOWN |
| created_at | DateTimeField | auto_now_add=True |  |
| updated_at | DateTimeField | auto_now=True |  |

### ResourceMetrics
| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| id | Integer | Primary Key, Auto-increment |  |
| machine | OneToOneField | Machine, CASCADE |  |
| cpu_usage | FloatField |  |  |
| cpu_cores | IntegerField |  |  |
| memory_used | FloatField |  | In GB |
| memory_total | FloatField |  | In GB |
| memory_usage | FloatField |  | Percentage |
| disk_used | FloatField |  | In GB |
| disk_total | FloatField |  | In GB |
| disk_usage | FloatField |  | Percentage |
| network_incoming | FloatField |  | Mbps |
| network_outgoing | FloatField |  | Mbps |
| timestamp | DateTimeField | auto_now=True |  |

## DHCP & TFTP Models

### IPPool
| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| id | Integer | Primary Key, Auto-increment |  |
| cidr | CharField | max_length=18 | e.g., "192.168.1.0/24" |
| gateway | GenericIPAddressField |  |  |
| description | TextField | blank=True |  |
| created_at | DateTimeField | auto_now_add=True |  |
| updated_at | DateTimeField | auto_now=True |  |

### Lease
| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| id | Integer | Primary Key, Auto-increment |  |
| ip_address | GenericIPAddressField |  |  |
| mac_address | CharField | max_length=17 |  |
| hostname | CharField | max_length=255, blank=True |  |
| lease_start | DateTimeField |  |  |
| lease_end | DateTimeField |  |  |
| binding_state | CharField | max_length=20, choices | active, expired, released, abandoned |
| last_transaction | DateTimeField |  |  |
| next_binding_state | CharField | max_length=20, choices | active, expired, released, abandoned |
| bootfile_url | CharField | max_length=255, blank=True |  |
| tftp_server | GenericIPAddressField | blank=True, null=True |  |
| ip_pool | ForeignKey | IPPool, CASCADE |  |
| created_at | DateTimeField | auto_now_add=True |  |
| updated_at | DateTimeField | auto_now=True |  |

### DHCPConfig
| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| id | Integer | Primary Key, Auto-increment |  |
| enabled | BooleanField | default=True |  |
| mode | CharField | max_length=20, default='server' |  |
| bind_address | GenericIPAddressField | default='0.0.0.0' |  |
| bind_interface | CharField | max_length=50, blank=True |  |
| tftp_ip | GenericIPAddressField | blank=True, null=True |  |
| tftp_port | IntegerField | default=69 |  |
| created_at | DateTimeField | auto_now_add=True |  |
| updated_at | DateTimeField | auto_now=True |  |

### TFTPConfig
| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| id | Integer | Primary Key, Auto-increment |  |
| enabled | BooleanField | default=True |  |
| bind_address | GenericIPAddressField | default='0.0.0.0' |  |
| bind_port | IntegerField | default=69 |  |
| block_size | IntegerField | default=512 |  |
| root_directory | CharField | max_length=255, default='/var/lib/tftpboot' |  |
| created_at | DateTimeField | auto_now_add=True |  |
| updated_at | DateTimeField | auto_now=True |  |

## IMS Django Models

### IMSWorker

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| id | Integer | Primary Key, Auto-increment |  |
| worker_id | CharField | max_length=100, unique=True | Could be container ID or hostname |
| ip_address | GenericIPAddressField |  |  |
| status | CharField | max_length=20, choices, default='inactive' | active, inactive, error |
| last_heartbeat | DateTimeField | auto_now=True |  |
| services | JSONField | default=dict | Stores DHCP/TFTP service status |
| metrics | JSONField | default=dict | Stores worker metrics |
| registered_at | DateTimeField | auto_now_add=True |  |
| cluster | ForeignKey | Cluster, SET_NULL, null=True, blank=True |  |

### IMSLease

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| id | Integer | Primary Key, Auto-increment |  |
| ip_address | GenericIPAddressField |  |  |
| mac_address | CharField | max_length=17 |  |
| hostname | CharField | max_length=255, blank=True |  |
| lease_start | DateTimeField |  |  |
| lease_end | DateTimeField |  |  |
| worker | ForeignKey | IMSWorker, CASCADE |  |
| cidr | CharField | max_length=18 | e.g., "192.168.1.0/24" |
| gateway | GenericIPAddressField |  |  |
| status | CharField | max_length=20, default='active' |  |

> *Meta: unique_together = ['ip_address', 'mac_address']*
> 

![image.png](assets/image.png)

- [x]  Integrate IMS-API rest authentication method with IMS-UI
    - This API will accommodate the authentication sequence that IMS-UI user and IMS-worker agent will use

**Current APIs**

![image.png](assets/image%201.png)

- Define APIs
    - [x]  Authentication API
    - [ ]  IMS-Worker API
        
        Active API that will be used to perform IMS related jobs
        
    - [ ]  OSC PM/FM API
        
        Predefined API that OSC already standarized.
        

- Create place holder for topology mapping of deployed cluster on IMS-UI
    
    ![image.png](assets/image%202.png)
    
- Add edit machine function to IMS-API backend, previously edit button from IMS-UI creating new machine instead of editing the existing one.
- Add proper service on IMS-UI to allow update of machine contents with dynamic path based on cluster ID and machine ID.
    - This way admin can edit which machine on which site using a single API call
        
        ![image.png](assets/image%203.png)
        
    

### IMS Worker

![image.png](assets/image%204.png)

- Integrate IMS-UI with IMS-API
    - Create API on IMS-API to allow machine information in database to be updated
- Add edit mechanism to machine list under a cluster section
- Implement Heartbeat on IMS-Worker
    - Heartbeats are the way for conccurent processes to signal life to outside parties, in our case IMS-Worker to IMS-API. This is needed to allow IMS-API to know about the realtime status of IMS related components such as DHCP, TFTP.
    - Need to decide whether IMS UI should get all of the realtime update from the site. This could lead to overload on the API and UI side.
    - 10s interval of self report

![image.png](assets/image%205.png)

![image.png](assets/image%206.png)

- Implement machine data fetching function on IMS-Worker through authenticated route. Allows IMS-Worker to serve only registered bare metals with registered Macaddress.
- ***Current integration phase***
    - ***Implementation Log:*** The IMS-UI and IMS-Worker are sharing the same sets of data now.

- Established contact to WindRVR guys if possible (They handle the Infra part of OSC)

**Authentication**

- *Skeleton Code*
    
    ```go
    // api/client.go
    package api
    
    import (
        "bytes"
        "encoding/json"
        "fmt"
        "net/http"
        "time"
        "sync"
    )
    
    type APIClient struct {
        baseURL     string
        workerID    string
        client      *http.Client
        authToken   string
        username    string
        password    string
        mu          sync.RWMutex
    }
    
    type AuthResponse struct {
        Access  string `json:"access"`
        Refresh string `json:"refresh"`
    }
    
    type WorkerStatus struct {
        Services map[string]ServiceStatus `json:"services"`
        Metrics  map[string]interface{}   `json:"metrics"`
    }
    
    type ServiceStatus struct {
        Status    string `json:"status"`
        LastError string `json:"last_error,omitempty"`
    }
    
    type LeaseInfo struct {
        IPAddress  string    `json:"ip_address"`
        MACAddress string    `json:"mac_address"`
        Hostname   string    `json:"hostname"`
        LeaseStart time.Time `json:"lease_start"`
        LeaseEnd   time.Time `json:"lease_end"`
        CIDR       string    `json:"cidr"`
        Gateway    string    `json:"gateway"`
    }
    
    func NewAPIClient(baseURL, workerID, username, password string) *APIClient {
        return &APIClient{
            baseURL:   baseURL,
            workerID:  workerID,
            username:  username,
            password:  password,
            client:    &http.Client{Timeout: 10 * time.Second},
        }
    }
    
    func (c *APIClient) login() error {
        data := map[string]string{
            "username": c.username,
            "password": c.password,
        }
    
        jsonData, err := json.Marshal(data)
        if err != nil {
            return fmt.Errorf("failed to marshal login data: %v", err)
        }
    
        resp, err := c.client.Post(
            c.baseURL+"/api/token/",
            "application/json",
            bytes.NewBuffer(jsonData),
        )
        if err != nil {
            return fmt.Errorf("login request failed: %v", err)
        }
        defer resp.Body.Close()
    
        if resp.StatusCode != http.StatusOK {
            return fmt.Errorf("login failed with status: %d", resp.StatusCode)
        }
    
        var authResp AuthResponse
        if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
            return fmt.Errorf("failed to decode auth response: %v", err)
        }
    
        c.mu.Lock()
        c.authToken = authResp.Access
        c.mu.Unlock()
    
        return nil
    }
    
    func (c *APIClient) getAuthHeader() string {
        c.mu.RLock()
        token := c.authToken
        c.mu.RUnlock()
        return "Bearer " + token
    }
    
    func (c *APIClient) doRequest(method, endpoint string, data interface{}) error {
        // Try request with current token
        err := c.doRequestWithAuth(method, endpoint, data)
        if err != nil && (err.Error() == "unauthorized" || err.Error() == "token expired") {
            // Try to login again
            if err := c.login(); err != nil {
                return fmt.Errorf("login retry failed: %v", err)
            }
            // Retry request with new token
            return c.doRequestWithAuth(method, endpoint, data)
        }
        return err
    }
    
    func (c *APIClient) doRequestWithAuth(method, endpoint string, data interface{}) error {
        jsonData, err := json.Marshal(data)
        if err != nil {
            return fmt.Errorf("failed to marshal data: %v", err)
        }
    
        req, err := http.NewRequest(
            method,
            c.baseURL+endpoint,
            bytes.NewBuffer(jsonData),
        )
        if err != nil {
            return fmt.Errorf("failed to create request: %v", err)
        }
    
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("Authorization", c.getAuthHeader())
    
        resp, err := c.client.Do(req)
        if err != nil {
            return fmt.Errorf("request failed: %v", err)
        }
        defer resp.Body.Close()
    
        if resp.StatusCode == http.StatusUnauthorized {
            return fmt.Errorf("unauthorized")
        }
    
        if resp.StatusCode != http.StatusOK {
            var errorResp map[string]interface{}
            if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
                return fmt.Errorf("request failed with status %d", resp.StatusCode)
            }
            return fmt.Errorf("request failed: %v", errorResp)
        }
    
        return nil
    }
    
    func (c *APIClient) Register(ipAddress string) error {
        // First ensure we're logged in
        if err := c.login(); err != nil {
            return fmt.Errorf("initial login failed: %v", err)
        }
    
        data := map[string]string{
            "worker_id": c.workerID,
            "ip_address": ipAddress,
        }
    
        return c.doRequest("POST", "/api/ims-worker/register/", data)
    }
    
    func (c *APIClient) SendHeartbeat(status WorkerStatus) error {
        data := map[string]interface{}{
            "worker_id": c.workerID,
            "services": status.Services,
            "metrics": status.Metrics,
        }
    
        return c.doRequest("POST", "/api/ims-worker/heartbeat/", data)
    }
    
    func (c *APIClient) ReportLease(lease LeaseInfo) error {
        data := map[string]interface{}{
            "worker_id": c.workerID,
            "lease": lease,
        }
    
        return c.doRequest("POST", "/api/ims-worker/report_lease/", data)
    }
    
    func (c *APIClient) ReportError(message string, details map[string]interface{}) error {
        data := map[string]interface{}{
            "worker_id": c.workerID,
            "error": map[string]interface{}{
                "message": message,
                "details": details,
            },
        }
    
        return c.doRequest("POST", "/api/ims-worker/report_error/", data)
    }
    ```
    

**Authentication Sequence**

![image.png](assets/image%207.png)

![image.png](assets/image%208.png)

**TFTP Function**

> Import from Outline
> 

**DHCP Function**

> Import from Outline
> 

## Deployment Scenario

| **Components** | **Remarks** |
| --- | --- |
| Operating System |  |
| Hypervisor |  |
| Cloud Platform | - OpenShift
- K8S |
| RAN | OAI/OSC |
| Automation Tools | Ansible, Terraform, etc. |

| **OS** | **Hypervisor** | **Cloud Platform** | **RAN** |
| --- | --- | --- | --- |
| Ubuntu |  ***None***  | K8S | OAI/OSC |
| Ubuntu | KVM | K8S | OAI/OSC |
|  |  |  |  |

## Lesson Learned

<aside>
⚠️ *Lesson learned*

</aside>

### OSC Development Status

1. OSC haven’t decide on IMS implementation procedure
    1. WindRVR is the main contributor 
2. Need to wait NYCU confirmation regarding their type of implementation

### GO Related

**Heartbeat & GO Routine**

- Heartbeats are the way for conccurent processes to signal life to outside parties, in our case IMS-Worker to IMS-API. This is needed to allow IMS-API to know about the realtime status of IMS related components such as DHCP, TFTP.
    - Need to decide whether IMS UI should get all of the realtime update from the site. This could lead to overload on the API and UI side.
- Two different types of heartbeats
    - Occur at time interval
    - Occur at the beginning of a unit work
- Utilization of heartbeart on IMS
    - Update the IMS-UI status of created clusters
    - Log leased DHCP IP
    - …

### Django Related

## Study Reference

- **Milestone**: [https://lf-o-ran-sc.atlassian.net/wiki/spaces/IN/pages/14385176/INF+O2+IMS+and+DMS+Spec+Compliance](https://lf-o-ran-sc.atlassian.net/wiki/spaces/IN/pages/14385176/INF+O2+IMS+and+DMS+Spec+Compliance)
- **Release:** [https://lf-o-ran-sc.atlassian.net/wiki/spaces/REL/pages/12812923/K+Release#Infrastructure-(INF)](https://lf-o-ran-sc.atlassian.net/wiki/spaces/REL/pages/12812923/K+Release#Infrastructure-(INF))
- **Guideline:** [https://lf-o-ran-sc.atlassian.net/wiki/spaces/IN/pages/137035779/INF+Deployment+Guideline+-+StarlingX+O-Cloud+-+AIO+Simplex](https://lf-o-ran-sc.atlassian.net/wiki/spaces/IN/pages/137035779/INF+Deployment+Guideline+-+StarlingX+O-Cloud+-+AIO+Simplex)

### RedHat O2 IMS Module

[https://github.com/openshift-kni/oran-o2ims](https://github.com/openshift-kni/oran-o2ims)

> *KNI: Kubernetes-native Infrastructure*
> 

The ORAN O2 IMS implementation in OpenShift is managed by the IMS operator. It configures the different components defined in the specification: the deployment manager service, the resource server, alarm server, subscriptions to resource and alert.

The IMS operator will create an O-Cloud API that will be available to be queried, for instance from a SMO. It also provides a configuration mechanism using a Kubernetes custom resource definition (CRD) that allows the hub cluster administrator to configure the different IMS microservices properly.

### WindRVR O2 IMS Proposal

**WindRVR Demo Scenario (Replicable)**

- OKD auto deployment
    - Ansible based automatic deployment of
- Multi-Arch support of OCloud Deployment
- StarlingX O-Cloud based automatic deployment
- ETSI-DMS based implementation

**API Structure: Register**

```json
{

	"globalCloudId": "",
	"oCloudId": "",
	"IMS_EP": "https://...:30205",
	"smo_token_data": {
		"iss": "o2ims",
		"aud": "smo",
		"smo_token_payload": "xxx",
		"smo_token_type": "jwt",
		"smo_token_expiration": "",
		"smo_token_algo": "RS256"
	}
}
```

- Follow their defined data structure to be implemented on our IMS module

**WindRVR Proposed Flow**

![windrvr-ims.png](assets/windrvr-ims.png)

![Service API for O2 IMS is not defined yet](assets/image%209.png)

Service API for O2 IMS is not defined yet

### NYCU O2 Implementation

> Ask Prof. for the PDF version of this
> 
> 
> [](https://thesis.lib.nycu.edu.tw/items/37ecdb53-9b4d-4ae3-bb85-614c3bd5701c)
> 

[NYCU O2 IMS Implementation Questions](https://www.notion.so/NYCU-O2-IMS-Implementation-Questions-175d924b024b80808dc4f61d0a6f4550?pvs=21)

| **Components** | **Context** | **Status on NYCU Implementation** |
| --- | --- | --- |
| **O2ims** |<ul><li>HTTP interface between SMO FOCOM and O-Cloud IMS</li> <li>Expose O-Cloud information to SMO</li></ul> | - Not shown any API call happened between SMO with IMS on the thesis report, implementation unclear. |
| **O2ims Provisioning API** | O2 Interface for Provisioning | <ul> <li>The shown IMS adaptor functions only cover the utilization of StarlingX in the Proxmox hypervisor. This doesn't cover other non-Proxmox deployments.</li><li>The implementation doesn't show any API calls being made between the IMS Core service and StarlingX adaptor, hence it is unclear whether there are any utilities.</li><li>The deployment of O-Cloud is performed using Ansible and has no correlation with any APIs that should manage the infrastructure creation.</li></ul> |
| O2ims Software Management Service |  | N/A, software used on the thesis is predefined by author |
| O2ims PM | Perfromance Monitoring |<ul><li>Defined by OSC, unclear it is used by NYCU implementation or not</li><li>Shown result can be completed without this component</li></ul> |
| O2ims  Inventory |  | <ul><li>Defined by OSC, unclear it is used by NYCU implementation or not<li>Shown result can be completed without this component </li></ul>|
| O2dms |  | All of the DMS components are done by OSM Mano and K8s. |

![O-Cloud Deployment Scenario by NYCU](assets/image%2010.png)

O-Cloud Deployment Scenario by NYCU

![image.png](assets/image%2011.png)

![image.png](assets/image%2012.png)

![image.png](assets/image%2013.png)

![image.png](assets/image%2014.png)

- Deployment are done by User the existence of API on the FOCOM side is questioned
- Initiate trigger that come into the FOCOM is unclear weather it is API called from somewhere (nobody knows where) or a user interaction.
- The AWX part of deployment shown no feedback is being given into FOCOM, hence the inventory and PM information is out of FOCOM’s vision as AWX had it’s own PM and Inventory System.

## Reports

### Presentation

[O2-Master-Thesis (1).pdf](assets/O2-Master-Thesis_(1).pdf)

### CallFlow HD

[BMW-Thesis-Call-Flow.pdf](assets/BMW-Thesis-Call-Flow.pdf)
