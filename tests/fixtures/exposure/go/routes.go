package routes

func Register(r *gin.Engine) {
	r.GET("/status", func(c *gin.Context) { c.Status(200) })
	admin := r.Group("/admin", AuthMiddleware())
	admin.GET("/stats", func(c *gin.Context) { c.Status(200) })
}
