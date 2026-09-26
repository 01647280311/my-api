app.post("/users", (req, res) => {
  const { name, age } = req.body;

  res.json({
    success: true,
    message: "User created successfully",
    user: {
      name: name,
      age: age
    }
  });
});
