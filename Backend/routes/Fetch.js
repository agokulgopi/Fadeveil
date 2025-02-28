const express = require('express');
const fs = require('fs');
const path = require('path');

const router = express.Router();
const UPLOADS_DIR = path.join(__dirname, '../uploads');

// API to fetch list of files
router.get('/files', (req, res) => {
    fs.readdir(UPLOADS_DIR, (err, files) => {
        if (err) {
            return res.status(500).json({ error: "Error reading uploads directory" });
        }

        const fileDetails = files.map((file, index) => ({
            id: index + 1,
            name: file
        }));

        res.json(fileDetails);
    });
});

module.exports = router;
