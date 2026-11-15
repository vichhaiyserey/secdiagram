package com.example;

@RestController
@RequestMapping("/api")
public class AdminApi {
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/secret")
    public String secret() { return "s"; }

    @PermitAll
    @GetMapping("/health")
    public String health() { return "ok"; }

    @GetMapping("/info")
    public String info() { return "i"; }
}
