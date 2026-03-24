typedef struct {
    uint16_t message_id;
    uint8_t buf_size;
    uint64_t payload;
} Frame;

typedef struct {
    uint16_t message_id;
    uint8_t start_bit[5];   //Start bits in the payload. Max 5 signals per frame
    uint8_t length[5];      //Length of section in payload. Max 5 signals per frame
    uint8_t ts_start_bit;   //!!!Don't use - Merge into other start_bits!!!
    float factor;           //Factor for scaling payload data. Multiple sensor data may require multiple
    float offset;           //Offset for payload data. Multiple sensor data may require multiple
    float min;              //For verification? Multiple sensor data may require multiple
    float max;              //For verification? Multiple sensor data may require multiple
    int device_id;
    int signal_count;       //Actual signal count
} SignalDef;

typedef struct {
    uint64_t ts_orig;       //necessary? Try not to use!!!
    uint64_t ts_universal;  //Calculated universal timestamp for sorting in EKF queue
    int device_id;
    int sig_idx;            //ID of signal (per device) to know what signal it is
    float value;            //Physical value
    int valid;              //health bits
} TelemetryPoint;

// Lock-Free Ring Queue
typedef struct {
    TelemetryPoint data[256];
    _Atomic uint32_t head; // Modified by CAN Interrupt (Producer)
    _Atomic uint32_t tail; // Modified by EKF (Consumer)
} Queue;

//SAMPLE device definitions
const SignalDef dev_lib[8] = {
    [0] = { .signal_count = 3, .device_id = 0, .ts_start_bit = 0, .start_bit = {8, 16, 32, 0, 0}, .length = 16, .factor = 1.0, .offset = 0 },  //GPS
    [1] = { .signal_count = 4, .device_id = 1, .ts_start_bit = 0, .start_bit = {8, 16, 32, 48, 0}, .length = 8,  .factor = 0.5, .offset = 0 }, //Acceleration Sensor
    // ...
};