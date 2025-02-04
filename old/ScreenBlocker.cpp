#include <Windows.h>
#include <d3d11.h>

bool BlockScreenCapture() {
    ID3D11Device* device;
    ID3D11DeviceContext* context;
    D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, D3D11_CREATE_DEVICE_DEBUG, NULL, 0, D3D11_SDK_VERSION, &device, NULL, &context);
    
    HDC hdc = GetDC(NULL);
    HBITMAP hbm = CreateCompatibleBitmap(hdc, 1, 1);
    SelectObject(hdc, hbm);
    BitBlt(hdc, 0, 0, 1, 1, hdc, 0, 0, BLACKNESS);
    
    return true;
}
